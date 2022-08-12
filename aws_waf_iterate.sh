#!/bin/bash

cat /dev/null > ~/.aws/credentials
iteratePyFile="aws_waf_iterate.py"
mergeFilesPFile="aws_waf_merge_files.py"

while read -r line
do
    
    account_id=$(echo "$line" | cut -d "," -f1)
    account_key=$(echo "$line" | cut -d "," -f2)
    account_name=$(echo "$line" | cut -d "," -f3)
    aws configure set aws_access_key_id "$account_id"
    aws configure set aws_secret_access_key "$account_key"
    aws configure set default.region eu-west-1
    line1=1
    substitute="accountName=\"$account_name\""
    sed -i "${line1}s/.*/$substitute/" $iteratePyFile
    
    regionarray=(
        "eu-west-1"
        "us-east-1"

    )
    for region in "${regionarray[@]}"
    do
        line2=2
        substitute="region=\"$region\""
        sed -i "${line2}s/.*/$substitute/" $iteratePyFile
        python3 "$iteratePyFile"


    done 

done < /home/dawsonpaul/.aws/new_creds.txt
#done < /home/dawsonpaul/.aws/new_creds_test.txt

python3 "$mergeFilesPFile"

