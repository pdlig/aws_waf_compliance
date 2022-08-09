accountName="diig"
region="us-east-1"
import boto3
import json
import re
import xlsxwriter
import itertools
from datetime import date
from collections import defaultdict
today = date.today()
date = today.strftime("%Y-%m-%d")
#####Account Number
id = boto3.client('sts').get_caller_identity().get('Account')
#####Account Name
#alias = boto3.client('iam').list_account_aliases()['AccountAliases'][0]
alias = accountName
#####Open Workbook for XLSX
workbook = xlsxwriter.Workbook('./output/_'+alias+'_'+region+'_'+date+'.xlsx')#./output_'+date+'/
cell_format = workbook.add_format()
cell_format.set_font_size(9)
###Opening Message###
print("Checking Account ID:", id, " Name:", alias, " Region: ",region)

#####Get Loadbalancer Information

client_elbv2 = boto3.client('elbv2', region_name=region)
describe_load_balancers = client_elbv2.describe_load_balancers()
lbNames=[]
lbArns=[]
for lb in (describe_load_balancers['LoadBalancers']):
    lbNames.append(lb['LoadBalancerName'])
    lbArns.append(lb['LoadBalancerArn'])

#####Functions


def get_loadbalancer(arn):
    get_lb = client_elbv2.describe_load_balancers(LoadBalancerArns=[
         arn,])
    return get_lb


def get_loadbalancerListener(arn): 
    get_lbListener = client_elbv2.describe_listeners(   
    LoadBalancerArn=arn,
   
)
    return get_lbListener


#Check if number in string for AssetID
def containsNumber(value):
    return any([char.isdigit() for char in value])


def fixlist(list):
    list=str(list)
    listfixed=list.strip('[]').replace('\'', '').replace(',','\n')
    return listfixed


##################### WebACL Rules #################################################################################
###Workbook Configuration ##############################
worksheet = workbook.add_worksheet("WebACL_Ruleset")
bold = workbook.add_format({'bold': True, 'font_size':10})
worksheet.write('A1', 'Account_Name', bold)
worksheet.write('B1', 'Account_ID', bold)
worksheet.write('C1', 'Region', bold)
worksheet.write('D1', 'WebACL_Name', bold)
worksheet.write('E1', 'Compliance', bold)
worksheet.write('F1', 'Location', bold)
worksheet.write('G1', 'Application', bold)
worksheet.write('H1', 'Owner', bold)
worksheet.write('I1', 'DefaultAction', bold)

worksheet.write('J1', 'RateLimitAction', bold)
worksheet.write('K1', 'Rate', bold)

worksheet.write('L1', 'IpReputation', bold)
worksheet.write('M1', 'IpReputationCount', bold)

worksheet.write('N1', 'AnonymousIpList', bold)
worksheet.write('O1', 'AnonymousIpListCount', bold)

worksheet.write('P1', 'CommonRuleSet', bold)
worksheet.write('Q1', 'CommonRuleSetCount', bold)

worksheet.write('R1', 'KnownBadInputs', bold)
worksheet.write('S1', 'KnownBadInputsCount', bold)

worksheet.write('T1', 'SQLiRuleSet', bold)
worksheet.write('U1', 'SQLiRuleSetCount', bold)

worksheet.write('V1', 'AdminProtect', bold)
worksheet.write('W1', 'AdminProtectCount', bold)

worksheet.write('X1', 'Linux', bold)
worksheet.write('Y1', 'LinuxCount', bold)

worksheet.write('Z1', 'Unix', bold)
worksheet.write('AA1', 'UnixCount', bold)

worksheet.write('AB1', 'Windows', bold)
worksheet.write('AC1', 'WindowsCount', bold)

worksheet.write('AD1', 'PHP', bold)
worksheet.write('AE1', 'PHPCount', bold)

worksheet.write('AF1', 'WordPress', bold)
worksheet.write('AG1', 'WordPressCount', bold)

worksheet.write('AH1', 'BotControl', bold)
worksheet.write('AI1', 'BotControlCount', bold)

worksheet.write('AJ1', 'AdvancedThreatProtect', bold)
worksheet.write('AK1', 'AdvancedThreatProtectCount', bold)




#####Workbook Conditional Formatting
format1 = workbook.add_format({'bg_color': '#FFC7CE',
                               'font_color': '#9C0006'})
format2 = workbook.add_format({'bg_color': '#C6EFCE',
                               'font_color': '#006100'})
format3 = workbook.add_format({'bg_color': '#FF9900',
                               'font_color': '#000000'})
format4 = workbook.add_format({'bg_color': '#076403',
                               'font_color': '#FFFFFF'})                               
#Pass / Green
#Rate Limiting 
worksheet.conditional_format('J2:J50', {'type':     'text',
                                        'criteria': 'containing',
                                        'value':    'Block',
                                        'format':   format2})
#WebACL Rules
worksheet.conditional_format('L2:P50', {'type':     'text',
                                        'criteria': 'containing',
                                        'value':    'Block',
                                        'format':   format2})
#Compliance                                        
worksheet.conditional_format('E2:E50', {'type':     'text',
                                        'criteria': 'begins with',
                                        'value':    'Compliant',
                                        'format':   format4})                                        

#Fail / Red
#Rate Limiting
worksheet.conditional_format('J2:J50', {'type':     'text',
                                        'criteria': 'containing',
                                        'value':    'Count',
                                        'format':   format1})
                                        
worksheet.conditional_format('J2:J50', {'type':     'text',
                                        'criteria': 'containing',
                                        'value':    'Unknown',
                                        'format':   format1})

worksheet.conditional_format('J2:J50', {'type':     'text',
                                        'criteria': 'containing',
                                        'value':    'Allow',
                                        'format':   format1})

#WebACL Rules
worksheet.conditional_format('L2:P50', {'type':     'text',
                                        'criteria': 'containing',
                                        'value':    'Count',
                                        'format':   format1})

#Compliance                                       
worksheet.conditional_format('E2:E50', {'type':     'text',
                                        'criteria': 'begins with',
                                        'value':    'NonCompliant',
                                        'format':   format3})                                                    
                    
##############################################################################
##### WebACL Rules
#########################

regional_client_wafv2 = boto3.client('wafv2', region_name=region)

list_web_acl_regional = regional_client_wafv2.list_web_acls(
    Scope='REGIONAL',
     )

global_client_wafv2 = boto3.client('wafv2', region_name='us-east-1')
list_web_acl_cloudfront = global_client_wafv2.list_web_acls(
    Scope='CLOUDFRONT',
     ) 


lbWafArns=[]
lbWithWafResults=[]
webAclRegionalArns=[]
webAclCloudfrontArns=[]
webACLRulesResults=[]
print("Checking Regional WebACLs")
##Regional WebACLS
compliantWebAclRulesNum=0
nonCompliantWebAclRulesNum=0
for regionalwebAclArn in list_web_acl_regional["WebACLs"]:
    location="regional"
    webAclName=regionalwebAclArn['Name']
    webAclId=regionalwebAclArn['Id']
    WebACLArn=regionalwebAclArn["ARN"]
    webAclRegionalArns.append(WebACLArn)
    webAclRegional=regional_client_wafv2.get_web_acl(Name=webAclName, Scope='REGIONAL', Id=webAclId)
    

    webAclCapacity=webAclRegional['WebACL']['Capacity']
    webAclDefaultAction=webAclRegional['WebACL']['DefaultAction']
    webAclDefaultAction=(''.join(webAclDefaultAction))
    action=[]
    rateLimitAction="NotConfigured"
    rateLimitRate="NotConfigured"
    ruleGroupName="NotConfigured"
    AWSManagedRulesAmazonIpReputationList="NotConfigured"
    AWSManagedRulesAnonymousIpList="NotConfigured"
    AWSManagedRulesCommonRuleSet="NotConfigured"
    AWSManagedRulesKnownBadInputsRuleSet="NotConfigured"
    AWSManagedRulesSQLiRuleSet="NotConfigured"
    AWSManagedRulesAdminProtectionRuleSet="NotConfigured"
    AWSManagedRulesLinuxRuleSet="NotConfigured"
    AWSManagedRulesUnixRuleSet="NotConfigured"
    AWSManagedRulesWindowsRuleSet="NotConfigured"
    AWSManagedRulesPHPRuleSet="NotConfigured"
    AWSManagedRulesWordPressRuleSet="NotConfigured"
    AWSManagedRulesBotControlRuleSet="NotConfigured"
    AWSManagedRulesATPRuleSet="NotConfigured"
    CommonRuleSetExcluded=""
    IpReputationListExcluded=""
    AnonymousIpListExcluded=""
    CommonRuleSetExcluded=""
    KnownBadInputsExcluded=""
    SQLiRuleSetExcluded=""
    AdminProtectionExcluded=""
    LinuxRuleSetExcluded=""
    UnixRuleSetExcluded=""
    WindowsRuleSetExcluded=""
    PHPRuleSetExcluded=""
    WordPressRuleSetExcluded=""
    BotControlRuleSetExcluded=""
    ATPRuleSetExcluded=""
    

    for webAclrules in webAclRegional['WebACL']['Rules']:


        if 'OverrideAction' in webAclrules:
            try:
             ruleGroupName=webAclrules['Statement']['ManagedRuleGroupStatement']['Name']
            except:
                pass
        
        try:
            rateLimitAction=webAclrules['Action']
            rateLimitAction=(''.join(rateLimitAction))
            rateLimitRate=webAclrules['Statement']['RateBasedStatement']['Limit']


        except:
            pass
        ruleName=webAclrules['Name']        
        
        try:
            ruleAction=webAclrules['OverrideAction']
            ruleAction=(''.join(ruleAction))
            if ruleAction=='None':
                ruleAction='RuleConfigured'
            if "ExcludedRules" in webAclrules['Statement']['ManagedRuleGroupStatement']:
                ruleAction='ConfiguredCount'

        
            if 'AWSManagedRulesAmazonIpReputationList' in  ruleGroupName:
                AWSManagedRulesAmazonIpReputationList=ruleAction
                IpReputationListExcluded=[]
                for item in webAclrules['Statement']['ManagedRuleGroupStatement']['ExcludedRules']:
                    name='count_'+item['Name']
                    IpReputationListExcluded.append(name)
                IpReputationListExcluded=str(IpReputationListExcluded).replace('\'', '').replace('\"', '').replace(',','\n').replace(' ','').strip('[]')
                if IpReputationListExcluded != "": ruleAction='ConfiguredCount'         
                    
                
            if 'AWSManagedRulesAnonymousIpList' in  ruleGroupName:
                AWSManagedRulesAnonymousIpList=ruleAction
                AnonymousIpListExcluded=[]
                for item in webAclrules['Statement']['ManagedRuleGroupStatement']['ExcludedRules']:
                    name='count_'+item['Name']
                    AnonymousIpListExcluded.append(name)
                AnonymousIpListExcluded=str(AnonymousIpListExcluded).replace('\'', '').replace('\"', '').replace(',','\n').replace(' ','').strip('[]')     
                
            if 'AWSManagedRulesCommonRuleSet' in ruleGroupName:
                AWSManagedRulesCommonRuleSet=ruleAction
                CommonRuleSetExcluded=[]
                for item in webAclrules['Statement']['ManagedRuleGroupStatement']['ExcludedRules']:
                    name='count_'+item['Name']
                    CommonRuleSetExcluded.append(name)
                CommonRuleSetExcluded=str(CommonRuleSetExcluded).replace('\'', '').replace('\"', '').replace(',','\n').replace(' ','').strip('[]')
                
                
            
                   
                
            if 'AWSManagedRulesKnownBadInputsRuleSet' in  ruleGroupName:
                AWSManagedRulesKnownBadInputsRuleSet=ruleAction
                KnownBadInputsExcluded=[]
                for item in webAclrules['Statement']['ManagedRuleGroupStatement']['ExcludedRules']:
                    name='count_'+item['Name']
                    KnownBadInputsExcluded.append(name)
                KnownBadInputsExcluded=str(KnownBadInputsExcluded).replace('\'', '').replace('\"', '').replace(',','\n').replace(' ','').strip('[]')                

            if 'AWSManagedRulesSQLiRuleSet' in  ruleGroupName:
                AWSManagedRulesSQLiRuleSet=ruleAction
                SQLiRuleSetExcluded=[]
                for item in webAclrules['Statement']['ManagedRuleGroupStatement']['ExcludedRules']:
                    name='count_'+item['Name']
                    SQLiRuleSetExcluded.append(name)
                SQLiRuleSetExcluded=str(SQLiRuleSetExcluded).replace('\'', '').replace('\"', '').replace(',','\n').replace(' ','').strip('[]')                      

            if 'AWSManagedRulesAdminProtectionRuleSet' in  ruleGroupName:
                AWSManagedRulesAdminProtectionRuleSet=ruleAction
                AdminProtectionExcluded=[]
                for item in webAclrules['Statement']['ManagedRuleGroupStatement']['ExcludedRules']:
                    name='count_'+item['Name']
                    AdminProtectionExcluded.append(name)
                AdminProtectionExcluded=str(AdminProtectionExcluded).replace('\'', '').replace('\"', '').replace(',','\n').replace(' ','').strip('[]')   


            if 'AWSManagedRulesLinuxRuleSet' in  ruleGroupName:
                AWSManagedRulesLinuxRuleSet=ruleAction
                LinuxRuleSetExcluded=[]
                for item in webAclrules['Statement']['ManagedRuleGroupStatement']['ExcludedRules']:
                    name='count_'+item['Name']
                    LinuxRuleSetExcluded.append(name)
                LinuxRuleSetExcluded=str(LinuxRuleSetExcluded).replace('\'', '').replace('\"', '').replace(',','\n').replace(' ','').strip('[]')   


            if 'AWSManagedRulesUnixRuleSet' in  ruleGroupName:
                AWSManagedRulesUnixRuleSet=ruleAction
                UnixRuleSetExcluded=[]
                for item in webAclrules['Statement']['ManagedRuleGroupStatement']['ExcludedRules']:
                    name='count_'+item['Name']
                    UnixRuleSetExcluded.append(name)
                UnixRuleSetExcluded=str(UnixRuleSetExcluded).replace('\'', '').replace('\"', '').replace(',','\n').replace(' ','').strip('[]')   

            
            if 'AWSManagedRulesWindowsRuleSet' in  ruleGroupName:
                AWSManagedRulesWindowsRuleSet=ruleAction
                WindowsRuleSetExcluded=[]
                for item in webAclrules['Statement']['ManagedRuleGroupStatement']['ExcludedRules']:
                    name='count_'+item['Name']
                    WindowsRuleSetExcluded.append(name)
                WindowsRuleSetExcluded=str(WindowsRuleSetExcluded).replace('\'', '').replace('\"', '').replace(',','\n').replace(' ','').strip('[]')   

            
            if 'AWSManagedRulesPHPRuleSet' in  ruleGroupName:
                AWSManagedRulesPHPRuleSet=ruleAction
                PHPRuleSetExcluded=[]
                for item in webAclrules['Statement']['ManagedRuleGroupStatement']['ExcludedRules']:
                    name='count_'+item['Name']
                    PHPRuleSetExcluded.append(name)
                PHPRuleSetExcluded=str(PHPRuleSetExcluded).replace('\'', '').replace('\"', '').replace(',','\n').replace(' ','').strip('[]')   


            if 'AWSManagedRulesWordPressRuleSet' in  ruleGroupName:
                AWSManagedRulesWordPressRuleSet=ruleAction
                WordPressRuleSetExcluded=[]
                for item in webAclrules['Statement']['ManagedRuleGroupStatement']['ExcludedRules']:
                    name='count_'+item['Name']
                    WordPressRuleSetExcluded.append(name)
                WordPressRuleSetExcluded=str(WordPressRuleSetExcluded).replace('\'', '').replace('\"', '').replace(',','\n').replace(' ','').strip('[]')   


            if 'AWSManagedRulesBotControlRuleSet' in  ruleGroupName:
                AWSManagedRulesBotControlRuleSet=ruleAction            
                BotControlRuleSetExcluded=[]
                for item in webAclrules['Statement']['ManagedRuleGroupStatement']['ExcludedRules']:
                    name='count_'+item['Name']
                    BotControlRuleSetExcluded.append(name)
                BotControlRuleSetExcluded=str(BotControlRuleSetExcluded).replace('\'', '').replace('\"', '').replace(',','\n').replace(' ','').strip('[]') 


            if 'AWSManagedRulesATPRuleSet' in  ruleGroupName:
                AWSManagedRulesATPRuleSet=ruleAction
                ATPRuleSetExcluded=[]
                for item in webAclrules['Statement']['ManagedRuleGroupStatement']['ExcludedRules']:
                    name='count_'+item['Name']
                    ATPRuleSetExcluded.append(name)
                ATPRuleSetExcluded=str(ATPRuleSetExcluded).replace('\'', '').replace('\"', '').replace(',','\n').replace(' ','').strip('[]') 


    

                
            
        except:
            pass
    if CommonRuleSetExcluded: ruleAction='ConfiguredCount' 

    if (rateLimitAction=="Block" and
        AWSManagedRulesAmazonIpReputationList =="Block" and
        AWSManagedRulesAnonymousIpList =="Block" and
        AWSManagedRulesCommonRuleSet =="Block" and
        AWSManagedRulesKnownBadInputsRuleSet =="Block"):
        compliance="Compliant"
        compliantWebAclRulesNum+=1
    else:
        compliance="NonCompliant"
        nonCompliantWebAclRulesNum+=1
    App="n/a"
    Owner="n/a"
    
        
    
    regionalAclResults=(alias, id, region, webAclName, compliance,location,App,Owner, webAclDefaultAction, rateLimitAction,rateLimitRate,
    AWSManagedRulesAmazonIpReputationList,str(IpReputationListExcluded).strip('[]') ,
    AWSManagedRulesAnonymousIpList,str(AnonymousIpListExcluded).strip('[]') ,
    AWSManagedRulesCommonRuleSet,str(CommonRuleSetExcluded).strip('[]') ,
    AWSManagedRulesKnownBadInputsRuleSet,str(KnownBadInputsExcluded).strip('[]') ,
    AWSManagedRulesSQLiRuleSet,str(SQLiRuleSetExcluded).strip('[]') ,
    AWSManagedRulesAdminProtectionRuleSet,str(AdminProtectionExcluded).strip('[]') ,
    AWSManagedRulesLinuxRuleSet,str(LinuxRuleSetExcluded).strip('[]') ,
    AWSManagedRulesUnixRuleSet,str(UnixRuleSetExcluded).strip('[]') ,
    AWSManagedRulesWindowsRuleSet,str(WindowsRuleSetExcluded).strip('[]') ,
    AWSManagedRulesPHPRuleSet,str(PHPRuleSetExcluded).strip('[]') ,
    AWSManagedRulesWordPressRuleSet,str(WordPressRuleSetExcluded).strip('[]') ,
    AWSManagedRulesBotControlRuleSet,str(BotControlRuleSetExcluded).strip('[]') ,
    AWSManagedRulesATPRuleSet,str(ATPRuleSetExcluded)
    )
    webACLRulesResults.append(regionalAclResults)
    del webAclName
    

    
#Cloudfront WebACLS
print("Checking Global WebACLs")
for cloudfrontWebAclArn in list_web_acl_cloudfront["WebACLs"]:
    location="global"
    webAclName=cloudfrontWebAclArn['Name']
    webAclId=cloudfrontWebAclArn['Id']
    WebACLArn=cloudfrontWebAclArn["ARN"]
    webAclCloudfrontArns.append(WebACLArn)
    webAclGlobal=global_client_wafv2.get_web_acl(Name=webAclName, Scope='CLOUDFRONT', Id=webAclId)

    webAclCapacity=webAclGlobal['WebACL']['Capacity']
    webAclDefaultAction=webAclGlobal['WebACL']['DefaultAction']
    webAclDefaultAction=(''.join(webAclDefaultAction))   
    action=[]
    rateLimitAction="NotConfigured"
    rateLimitRate="NotConfigured"
    ruleGroupName="NotConfigured"
    AWSManagedRulesAmazonIpReputationList="NotConfigured"
    AWSManagedRulesAnonymousIpList="NotConfigured"
    AWSManagedRulesCommonRuleSet="NotConfigured"
    AWSManagedRulesKnownBadInputsRuleSet="NotConfigured"
    AWSManagedRulesSQLiRuleSet="NotConfigured"
    AWSManagedRulesAdminProtectionRuleSet="NotConfigured"
    AWSManagedRulesLinuxRuleSet="NotConfigured"
    AWSManagedRulesUnixRuleSet="NotConfigured"
    AWSManagedRulesWindowsRuleSet="NotConfigured"
    AWSManagedRulesPHPRuleSet="NotConfigured"
    AWSManagedRulesWordPressRuleSet="NotConfigured"
    AWSManagedRulesBotControlRuleSet="NotConfigured"
    AWSManagedRulesATPRuleSet="NotConfigured"

    for webAclrules in webAclGlobal['WebACL']['Rules']:
        if 'OverrideAction' in webAclrules:
            try:
                ruleGroupName=webAclrules['Statement']['ManagedRuleGroupStatement']['Name']
            except:
                pass
        
        try:
            rateLimitAction=webAclrules['Action']
            rateLimitAction=(''.join(rateLimitAction))
            rateLimitRate=webAclrules['Statement']['RateBasedStatement']['Limit']


        except:
            pass 
        
        try:
            ruleAction=webAclrules['OverrideAction']
            ruleAction=(''.join(ruleAction))
            if ruleAction=='None':
                ruleAction='Configured'

        
            if 'AWSManagedRulesAmazonIpReputationList' in  ruleGroupName:
                AWSManagedRulesAmazonIpReputationList=ruleAction
                
            if 'AWSManagedRulesAnonymousIpList' in  ruleGroupName:
                AWSManagedRulesAnonymousIpList=ruleAction
                
            if 'AWSManagedRulesCommonRuleSet' in ruleGroupName:
                AWSManagedRulesCommonRuleSet=ruleAction
                
            if 'AWSManagedRulesKnownBadInputsRuleSet' in  ruleGroupName:
                AWSManagedRulesKnownBadInputsRuleSet=ruleAction        

            if 'AWSManagedRulesSQLiRuleSet' in  ruleGroupName:
                AWSManagedRulesSQLiRuleSet=ruleAction

            if 'AWSManagedRulesAdminProtectionRuleSet' in  ruleGroupName:
                AWSManagedRulesAdminProtectionRuleSet=ruleAction

            if 'AWSManagedRulesLinuxRuleSet' in  ruleGroupName:
                AWSManagedRulesLinuxRuleSet=ruleAction

            if 'AWSManagedRulesUnixRuleSet' in  ruleGroupName:
                AWSManagedRulesUnixRuleSet=ruleAction
            
            if 'AWSManagedRulesWindowsRuleSet' in  ruleGroupName:
                AWSManagedRulesWindowsRuleSet=ruleAction
            
            if 'AWSManagedRulesPHPRuleSet' in  ruleGroupName:
                AWSManagedRulesPHPRuleSet=ruleAction

            if 'AWSManagedRulesWordPressRuleSet' in  ruleGroupName:
                AWSManagedRulesWordPressRuleSet=ruleAction

            if 'AWSManagedRulesBotControlRuleSet' in  ruleGroupName:
                AWSManagedRulesBotControlRuleSet=ruleAction            

            if 'AWSManagedRulesATPRuleSet' in  ruleGroupName:
                AWSManagedRulesATPRuleSet=ruleAction     

                

            
        except:
            pass
        
    if (rateLimitAction=="Block" and
        AWSManagedRulesAmazonIpReputationList =="Block" and
        AWSManagedRulesAnonymousIpList =="Block" and
        AWSManagedRulesCommonRuleSet =="Block" and
        AWSManagedRulesKnownBadInputsRuleSet =="Block"):
        compliance="Compliant"
        compliantWebAclRulesNum+=1
    else:
        compliance="NonCompliant"
        nonCompliantWebAclRulesNum+=1
        
    App="n/a"
    Owner="n/a"

    globalAclResults=(alias, id, region, webAclName, compliance,location,App,Owner, webAclDefaultAction, rateLimitAction,rateLimitRate,AWSManagedRulesAmazonIpReputationList,AWSManagedRulesAnonymousIpList,AWSManagedRulesCommonRuleSet,
    AWSManagedRulesKnownBadInputsRuleSet,AWSManagedRulesSQLiRuleSet,AWSManagedRulesAdminProtectionRuleSet,AWSManagedRulesLinuxRuleSet,AWSManagedRulesUnixRuleSet,AWSManagedRulesWindowsRuleSet,AWSManagedRulesPHPRuleSet,AWSManagedRulesWordPressRuleSet,AWSManagedRulesBotControlRuleSet,AWSManagedRulesATPRuleSet)
    webACLRulesResults.append(globalAclResults)
    del webAclName



for row_num, row_data in enumerate((webACLRulesResults),1):
    for col_num, col_data in enumerate(row_data):
     worksheet.write(row_num, col_num, col_data,cell_format)

lbWithWafResultsNum = len(lbWithWafResults)

##Sum of regional and cloudfront WebACLS

allWebAclNum=len(webAclRegionalArns)+len(webAclCloudfrontArns)
loggingConfiguredNum=0
loggingNotConfiguredNum=0

############################# Logging ########################################################################################
#Get Logging Configuration for Regional and Cloudfront WebACLs.
##################### WebACL Logging
###Workbook Configuration
worksheet = workbook.add_worksheet("WebACL_Logging")
bold = workbook.add_format({'bold': True, 'font_size':10})
worksheet.write('A1', 'Account_Name', bold)
worksheet.write('B1', 'Account_ID', bold)
worksheet.write('C1', 'Region', bold)
worksheet.write('D1', 'WebACL_Name', bold)
worksheet.write('E1', 'Logging', bold)
worksheet.write('F1', 'Asset_ID', bold)
worksheet.write('G1', 'Resource_Owner', bold)
######################################################
##### Logging
##############################
print("Checking Logging")

webAclLoggingResults=[]
row=1
for Arn in itertools.chain(webAclRegionalArns,webAclCloudfrontArns):
    
    awsArnSplit=Arn
    a,b,c,d,e,f,g,webAclSplit,webAclId = re.split(':|\/', awsArnSplit)
    loggingConfigured="NotLogging"
    try:
        get_logging_configuration = regional_client_wafv2.get_logging_configuration(ResourceArn=Arn)
        loggingConfig=get_logging_configuration['LoggingConfiguration']['LogDestinationConfigs'][0]
        if loggingConfig:
            loggingConfigured="Logging"
            worksheet.write_comment(row,3, loggingConfig, {'width': 800, 'height': 20, 'color': '#FF9900', 'font_size': 10 },  )
            row +=1
            loggingConfiguredNum +=1
    except:
        row += 1
        loggingNotConfiguredNum +=1
        pass


    webAclLogging=(alias, id, region, webAclSplit,loggingConfigured)
    webAclLoggingResults.append(webAclLogging)
    del webAclSplit


for row_num, row_data in enumerate((webAclLoggingResults),1):
    for col_num, col_data in enumerate(row_data):
     worksheet.write(row_num, col_num, col_data, cell_format)


lbWithWafResultsNum = len(lbWithWafResults)  

######Loadbalancer WebACLs
# #################### Loadbalancers With WAF
# ##Workbook Configuration
worksheet = workbook.add_worksheet("LBs_With_WAF")
bold = workbook.add_format({'bold': True, 'font_size':10})
worksheet.write('A1', 'Account_Name', bold)
worksheet.write('B1', 'Account_ID', bold)
worksheet.write('C1', 'Region', bold)
worksheet.write('D1', 'LB_Name', bold)
worksheet.write('E1', 'LB_Type', bold)
worksheet.write('F1', 'WebACL', bold)
worksheet.write('G1', 'Asset_ID', bold)
worksheet.write('H1', 'Resource_Owner', bold)
#############################################################################

print("Checking Loadbalancers With WAF")
#Regional WebACLS
for regionalwebAclArn in list_web_acl_regional["WebACLs"]:
    webAclName=regionalwebAclArn['Name']
    webAclId=regionalwebAclArn['Id']
    WebACLArn=regionalwebAclArn["ARN"]
    webAcl=regional_client_wafv2.get_web_acl(Name=webAclName, Scope='REGIONAL', Id=webAclId)
    webAclCapacity=webAcl['WebACL']['Capacity']
    webAclDefaultAction=webAcl['WebACL']['DefaultAction']
    webAclDefaultAction=(''.join(webAclDefaultAction))

    lb_list_resources_for_web_acl = regional_client_wafv2.list_resources_for_web_acl(
        WebACLArn=WebACLArn, ResourceType='APPLICATION_LOAD_BALANCER' )

    for resourceArn in lb_list_resources_for_web_acl["ResourceArns"]:
            lbWafArns.append(resourceArn)
            lb=get_loadbalancer(resourceArn)
            lbName=lb['LoadBalancers'][0]['LoadBalancerName']
            lbType=lb['LoadBalancers'][0]['Type']
            tags = client_elbv2.describe_tags(
                ResourceArns=[
                    resourceArn,])

            lbResultsList=(alias, id, region, lbName ,lbType, webAclName)
            lbWithWafResults.append(lbResultsList)
            del lbName


for row_num, row_data in enumerate((lbWithWafResults),1):
    for col_num, col_data in enumerate(row_data):
     worksheet.write(row_num, col_num, col_data, cell_format)


lbWithWafResultsNum = len(lbWithWafResults)

# # # ################### Loadbalancers Without WAF

##Workbook Configuration
worksheet = workbook.add_worksheet("LBs_Without_WAF")
bold = workbook.add_format({'bold': True, 'font_size':10})
worksheet.write('A1', 'Account_Name', bold)
worksheet.write('B1', 'Account_ID', bold)
worksheet.write('C1', 'Region', bold)
worksheet.write('D1', 'LB_Name', bold)
worksheet.write('E1', 'LB_Type', bold)
worksheet.write('F1', 'LB_Internet', bold)
worksheet.write('G1', 'WAF_Attached', bold)
worksheet.write('H1', 'Port', bold)
worksheet.write('I1', 'Protocol', bold)
worksheet.write('J1', 'Asset_ID', bold)
worksheet.write('K1', 'Resource_Owner', bold)
# #############################################################################


print("Checking Loadbalancers Without WAF")
lbsWithoutWaf = [x for x in lbArns if x not in lbWafArns ]
lbWithoutWafResults=[]
for loadbalancer in lbsWithoutWaf:
 describe_load_balancers = client_elbv2.describe_load_balancers(
     LoadBalancerArns=[
        loadbalancer,
    ],
 )
 for lb in describe_load_balancers['LoadBalancers']:
     lbArn=lb['LoadBalancerArn']  
      
     lbListener=get_loadbalancerListener(lbArn)
     try:
        lbListenerPort="null"
        lbListenerPort=lbListener['Listeners'][0]['Port']
        lbListenerProtocol=lbListener['Listeners'][0]['Protocol']
     except:
        pass
     if lb['Scheme'] == 'internet-facing':
      lbWithoutWaf=(alias, id, region , lb['LoadBalancerName'], lb['Type'], "internet-facing","No_WAF",lbListenerPort,lbListenerProtocol)
      lbWithoutWafResults.append(lbWithoutWaf)


lbWithoutWafResultsNum=(len(lbWithoutWafResults))

for row_num, row_data in enumerate((lbWithoutWafResults),1):
    for col_num, col_data in enumerate(row_data):
     worksheet.write(row_num, col_num, col_data,cell_format)
     

# # # # ##################################################################### API Gateway  ################################################################################
# # # # ############Session Information:
client_apigateway = boto3.client('apigateway', region_name=region) #apigatewayv2 doesn't support WAF
####Workbook Configuration
worksheet = workbook.add_worksheet("API_Gateways")
bold = workbook.add_format({'bold': True, 'font_size':10})
worksheet.write('A1', 'Account_Name', bold)
worksheet.write('B1', 'Account_ID', bold)
worksheet.write('C1', 'Region', bold)
worksheet.write('D1', 'Api_Name', bold)
worksheet.write('E1', 'Api_Type', bold)
worksheet.write('F1', 'Api_ID', bold)
worksheet.write('G1', 'Api_Stage', bold)
worksheet.write('H1', 'IP_Access_Policy', bold)
worksheet.write('I1', 'Web_Acl_Name', bold)
worksheet.write('J1', 'Web_Acl_ID', bold)
worksheet.write('K1', 'Asset_ID', bold)
worksheet.write('L1', 'Resource_Owner', bold)
# # ###############################################################
print("Checking API Gateways")
Stage="arn:aws:apigateway:region::/restapis/api-id/stages/stage-name"
get_rest_apis = client_apigateway.get_rest_apis(limit=499)
restApiIds=[]
apiResults=[]
apiResultsWaf=[]
apiResultsNoWaf=[]
row=1
for apiGateway in get_rest_apis['items']:
 checkApipolicy = "policy" in apiGateway
 apiGatewayName=apiGateway['name']
 restApiIds=apiGateway['id']
 restApiArn="arn:aws:apigateway:{}::/restapis/{}".format(region,restApiIds)     
 restApiType=apiGateway['endpointConfiguration']['types'][0]
 if checkApipolicy == True:
  checkApipolicyResult="policyAttached"
  apiPolicy = dict()
 try:
     apiPolicy = apiGateway['policy']
     apiPolicy=apiPolicy.replace("\\", "") 
     apiPolicyJson=json.loads(apiPolicy)
     apiPolicy=json.dumps(apiPolicyJson, indent=4, sort_keys=True, default=str)
     worksheet.write_comment(row, 6, apiPolicy, {'width': 800, 'height': 800, 'color': '#FF9900', 'font_size': 10 },  )
     row += 1
     
 except  KeyError:
      pass     

 if checkApipolicy != True:
    row += 1
    
    checkApipolicyResult="NoPolicy"

 get_api_stages = client_apigateway.get_stages(
    restApiId=restApiIds
  ) 
 for api_stage in get_api_stages['item']:
   
    stageName=api_stage['stageName']
    webAclArnexists = "webAclArn" in api_stage

    if webAclArnexists == True:
        webAclArn=api_stage['webAclArn']
        awsArnSplit=api_stage['webAclArn']
        try:
         a,b,c,d,e,f,g,webAcl,webAclId = re.split(':|\/', awsArnSplit)
        except:
            webAcl="ArnError"
            WebAclId="ArnError"
            pass       
        apiResultsList=(alias, id, region,apiGatewayName,restApiType,restApiIds,stageName,checkApipolicyResult,webAcl,webAclId)
        apiResults.append(apiResultsList)
        apiResultsWaf.append(apiResultsList)

    else:
        apiResultsList=(alias, id, region,apiGatewayName,restApiType,restApiIds,stageName,checkApipolicyResult,"null","null")
        apiResults.append(apiResultsList)
        apiResultsNoWaf.append(apiResultsList)

         
for row_num, row_data in enumerate((apiResults),1):
    for col_num, col_data in enumerate(row_data):
     worksheet.write(row_num, col_num, col_data,cell_format)

    lastrowAdd=str(row_num+3)
    imagePlace=("A"+lastrowAdd)


apiResultsNoWafNum=(len(apiResultsNoWaf))
apiResultsWafNum=len(apiResultsWaf)



###################################################################### CloudFront  #########################################################
####Workbook Configuration
worksheet = workbook.add_worksheet("Cloudfront")
bold = workbook.add_format({'bold': True, 'font_size':10})
worksheet.write('A1', 'Account_Name', bold)
worksheet.write('B1', 'Account_ID', bold)
worksheet.write('C1', 'Cloudfront_ID', bold)
worksheet.write('D1', 'WAF_Attached', bold)
worksheet.write('E1', 'Web_Acl_Name', bold)
worksheet.write('F1', 'Asset_ID', bold)
worksheet.write('G1', 'Resource_Owner', bold)
####################################################################
#####CloudFront 
print("Checking Cloudfront Distributions")
client_cloudfront = boto3.client('cloudfront')
cloudFrontResults=[]
list_distributions = client_cloudfront.list_distributions()
cloudfrontArns=[]
try:
 for cloudfront in list_distributions['DistributionList']['Items']:
  cloudfrontId=cloudfront['Origins']['Items'][0]['Id']
  cloudfrontArns.append(cloudfront['ARN'])
  webAclId=cloudfront['WebACLId']
  if len(cloudfront['WebACLId'])==0:
   cloudfrontWaf="noWebAcl"
   WebAclNameCf="noWebAcl"
  else:
    a,b,WebAclNameCf,d = re.split('/', webAclId) 
    cloudfrontWaf="WebAcl"

  cfResults=(alias, id, cloudfrontId,cloudfrontWaf,WebAclNameCf)
  cloudFrontResults.append(cfResults)
except:
    pass

    

for row_num, row_data in enumerate((cloudFrontResults),1):
    for col_num, col_data in enumerate(row_data):
     worksheet.write(row_num, col_num, col_data,cell_format)




###################################################################### Route53 #########################################################
####Workbook Configuration
worksheet = workbook.add_worksheet("Route53")
bold = workbook.add_format({'bold': True, 'font_size':10})
worksheet.write('A1', 'Account_Name', bold)
worksheet.write('B1', 'Account_ID', bold)
worksheet.write('C1', 'Zone_Name', bold)
worksheet.write('D1', 'Zone_ID', bold)
worksheet.write('E1', 'Records', bold)
worksheet.write('F1', 'Asset_ID', bold)
worksheet.write('G1', 'Resource_Owner', bold)
####################################################################
#####Route53
print("Checking Route53 Hosted Zones")
client_route53 = boto3.client('route53')
route53Results=[]
route53Arns=[]
list_hosted_zones = client_route53.list_hosted_zones_by_name()

for hostedZoneIds in list_hosted_zones['HostedZones']:
    hostedZoneId = hostedZoneIds['Id']
    route53Arn="arn:aws:route53:::{}".format(hostedZoneId)
    route53Arns.append(route53Arn)
    hostedZoneName= hostedZoneIds['Name']
    get_hosted_zone = client_route53.get_hosted_zone(Id=hostedZoneId)
    a,b,splitId = re.split('/', hostedZoneId)       
    recordCount=get_hosted_zone['HostedZone']['ResourceRecordSetCount']

    list_tags_for_resource = client_route53.list_tags_for_resource(
    ResourceType='hostedzone',
    ResourceId=splitId)

    r53Results=(alias, id, hostedZoneName,hostedZoneId,recordCount)
    route53Results.append(r53Results)

for row_num, row_data in enumerate((route53Results),1):
    for col_num, col_data in enumerate(row_data):
     worksheet.write(row_num, col_num, col_data,cell_format)

    

#################################################################### Elastic IP ##########################################################
####Workbook Configuration
worksheet = workbook.add_worksheet("Elastic_IP")
bold = workbook.add_format({'bold': True, 'font_size':10})
worksheet.write('A1', 'Account_Name', bold)
worksheet.write('B1', 'Account_ID', bold)
worksheet.write('C1', 'Region', bold)
worksheet.write('D1', 'EIP_Allocation', bold)
worksheet.write('E1', 'Public_IP', bold)
worksheet.write('F1', 'Private_IP', bold)
worksheet.write('G1', 'Asset_ID', bold)
worksheet.write('H1', 'Resource_Owner', bold)
#############################################################
############## Elastic IP
print("Checking Elastic IP Addresses")
elasticIpResults=[]
client_ec2 = boto3.client('ec2', region)
ec2_describe_addresses = client_ec2.describe_addresses()
eipArns=[]
for eip in ec2_describe_addresses['Addresses']:
    privateIp="null"
    allocationId="null"
    networkBorderGroup="null"
    privateIp="null"
    elasticIp="null"

    try:
        allocationId=eip['AllocationId']
        elasticIp=eip['PublicIp']
        privateIp=eip['PrivateIpAddress']
        networkBorderGroup=eip['NetworkBorderGroup']
        NetworkInterfaceOwnerId=eip['NetworkInterfaceOwnerId']
        eipArn='arn:aws:ec2:'+region+':'+NetworkInterfaceOwnerId+':eip-allocation/'+allocationId
        eipArns.append(eipArn)
    except:
        pass

    eipResults=(alias, id, region, allocationId,elasticIp,privateIp)
    elasticIpResults.append(eipResults)

for row_num, row_data in enumerate((elasticIpResults),1):
    for col_num, col_data in enumerate(row_data):
     worksheet.write(row_num, col_num, col_data)
 


#################################################################### Global Accelerator ##########################################################
####Workbook Configuration
worksheet = workbook.add_worksheet("Global_Accelerator")
bold = workbook.add_format({'bold': True, 'font_size':10})
worksheet.write('A1', 'Account_Name', bold)
worksheet.write('B1', 'Account_ID', bold)
worksheet.write('C1', 'Name', bold)
worksheet.write('D1', 'Asset_ID', bold)
worksheet.write('E1', 'Resource_Owner', bold)
#######################################################################
#####Global Accelerator

client_globalAccel = boto3.client('globalaccelerator', region_name="us-west-2")
list_accelerators = client_globalAccel.list_accelerators()
globalAcceleratorResults=[]
AcceleratorArns=[]
for ga in list_accelerators['Accelerators']:
    AcceleratorArn=ga['AcceleratorArn']
    AcceleratorArns.append(AcceleratorArn)
    gaName=ga['Name']
 
    gaResults=(alias, id, gaName)
    globalAcceleratorResults.append(gaResults)


for row_num, row_data in enumerate((globalAcceleratorResults),1):
    for col_num, col_data in enumerate(row_data):
     worksheet.write(row_num, col_num, col_data)
 

workbook.close()
print("Done! Results File:" 'DID_'+alias+'_'+region+'_'+date+'.xlsx')