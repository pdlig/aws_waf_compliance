account="sed replacement from aws_waf_iterate.sh"
region="sed replacement from aws_waf_iterate.sh"
########################################################
import glob
import pandas as pd
from datetime import date
today = date.today()
date = today.strftime("%Y-%m-%d")
files = 'output/*.xlsx'
excel_files= glob.glob(files)
###############################
from collections import defaultdict

worksheet_lists = defaultdict(list)
for file_name in excel_files:
    workbook = pd.ExcelFile(file_name, engine="openpyxl")
    for sheet_name in workbook.sheet_names:
         worksheet = workbook.parse(sheet_name)
         worksheet_lists[sheet_name].append(worksheet)

worksheets = {
    sheet_name: pd.concat(sheet_list)
        for (sheet_name, sheet_list)
        in worksheet_lists.items()
}


writer = pd.ExcelWriter('Aws_Merged_'+date+'.xlsx')

for sheet_name, df in worksheets.items():
    df = df.drop_duplicates()
    df.to_excel(writer, sheet_name=sheet_name, index=False)

writer.save()