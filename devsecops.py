"""
devsecops.py

This is what our team came up with for offering Unicorn group DevSecOps...
Maybe a semi standard solution would have been better like:
https://aws.amazon.com/answers/devops/aws-cloudformation-validation-pipeline/
or
https://aws.amazon.com/blogs/devops/implementing-devsecops-using-aws-codepipeline/

Another team will *hopefully* close the loop doing dynamic analysis with:
AWS Cloudwatch Events & AWS Config Rules, or things like:
https://github.com/capitalone/cloud-custodian
https://github.com/Netflix/security_monkey

And because DevSecOps is also about broadening the shared responsibility of security,
as well as automation, we have a basic function here for publishing to a Slack channel.

"""
import ruamel.yaml
import json
import base64
from urllib.parse import urljoin
from urllib.parse import urlencode
import urllib.request as urlrequest

#Configure these to Slack for ChatOps
SLACK_CHANNEL = 'jorgedevsecops' #Slack Channel to target
HOOK_URL = 'https://hooks.slack.com/services/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' #Like https://hooks.slack.com/services/T3KsdfVTL/B3dfNJ4V8/HmsgdXdzjW16pAD3CdASQChI

# Helper Function to enable us to put visibility into chat ops. Also outputs to Cloudwatch Logs.
# The Slack channel to send a message to stored in the slackChannel environment variable
def send_slack(message, username="SecurityBot", emoji=":exclamation:"):
    print(message)
    if not HOOK_URL:
        return None
    slack_message = {
        'channel': SLACK_CHANNEL,
        'text': message,
         "username": username
    }
    try:
        opener = urlrequest.build_opener(urlrequest.HTTPHandler())
        payload_json = json.dumps(slack_message)
        data = urlencode({"payload": payload_json})
        req = urlrequest.Request(HOOK_URL)
        response = opener.open(req, data.encode('utf-8')).read()
        return response.decode('utf-8')
    except:
        print("Slack connection failed. Valid webhook?")
        return None
        
# Define a YAML reader for parsing Cloudformation to handle !Functions like Ref
def general_constructor(loader, tag_suffix, node):
    return node.value
ruamel.yaml.SafeLoader.add_multi_constructor(u'!', general_constructor)

# Define basic security globals
SECURE_PORTS = ["443","22"]
DB_PORTS = ["3306"]
TAGS = ["Name", "Role", "Owner", "CostCenter"]

#Our DevSecOps Logic
def handler(event, context):
    yaml = base64.b64decode(event['b64template'])
    cfn = ruamel.yaml.safe_load(yaml)
    
    # We return result for scoring. it needs a policyN entry for every rule, with count of violations.
    # Errors is for informational purposes, and not required for scoring
    result = {
        "pass":True,
        "policy0":0,
        "policy1":0, 
        "policy2":0, 
        "policy3":0,
        "errors":[]
    }
    
    send_slack("BUILD: Starting DevSecOps static code analysis of CFN template: {}".format(cfn['Description']))
    
    ########################YOUR CODE GOES UNDER HERE########################
    #Now we loop over resources in the template, looking for policy breaches
    for resource in cfn['Resources']:
        #Test for Security Groups for Unicorn Security policy0
        ############# POLICY 0 ######
        if cfn['Resources'][resource]["Type"] == """AWS::EC2::SecurityGroup""":
            if "SecurityGroupIngress" in cfn['Resources'][resource]["Properties"]:
                for rule in cfn['Resources'][resource]["Properties"]['SecurityGroupIngress']:

                    send_slack("BUILD: Found SG rule: {}".format(rule))

                    #Test that SG ports are only 22 or 443 if open to /0
                    if "CidrIp" in rule:
                        if (rule["FromPort"] not in SECURE_PORTS or rule["ToPort"] not in SECURE_PORTS) and rule["CidrIp"] == '0.0.0.0/0':
                            result['pass'] = False
                            result['policy0'] += 1 #Add one to our policy fail counter
                            result["errors"].append("policy0: Port {} not allowed for /0".format(rule["FromPort"]))

                        #lets catch ranges (i.e 22-443)
                        if rule["FromPort"] != rule["ToPort"] and rule["CidrIp"] == '0.0.0.0/0':
                            result['pass'] = False
                            result['policy0'] += 1 #Add one to our policy fail counter
                            result["errors"].append("policy0: Port range {}-{} in not allowed for /0".format(rule["FromPort"],rule["ToPort"]))
                            
                        if rule["FromPort"] in DB_PORTS and rule["ToPort"] in DB_PORTS:
                            result['pass'] = False
                            result['policy0'] += 1
                            result['errors'].append('policy0: You need to be a part of WebServerSecurityGroup to use ports {} {}'.format(rule['FromPort'], rule['ToPort']))
                    if 'SourceSecurityGroupName' in rule:
                        if rule["FromPort"] in DB_PORTS and rule["ToPort"] in DB_PORTS and rule["SourceSecurityGroupName"] != 'WebServerSecurityGroup':
                            result['pass'] = False
                            result['policy0'] += 1
                            result['errors'].append('policy0: You need to be a part of WebServerSecurityGroup to use ports {} {}'.format(rule['FromPort'], rule['ToPort']))
                            
        if cfn['Resources'][resource]["Type"] == """AWS::S3::Bucket""":
            if "Properties" in cfn['Resources'][resource]:
                if "AccessControl" in cfn['Resources'][resource]["Properties"]:
                    if cfn['Resources'][resource]['Properties']['AccessControl'] == 'PublicRead':
                        result['pass'] = False
                        result['policy0'] += 1
                        result['errors'].append('policy0: S3 buckets cannot have {} AccessControl'.format(cfn['Resources'][resource]['Properties']['AccessControl']))
                    if cfn['Resources'][resource]['Properties']['AccessControl'] == 'PublicReadWrite':
                        result['pass'] = False
                        result['policy0'] += 1
                        result['errors'].append('policy0: S3 buckets cannot have {} AccessControl'.format(cfn['Resources'][resource]['Properties']['AccessControl']))

        ########## POLICY 1 ########
        if cfn['Resources'][resource]["Type"] == """AWS::IAM::User""":
            if "Properties" in cfn['Resources'][resource]:
                if "Policies" in cfn['Resources'][resource]['Properties']:
                    for policy in cfn['Resources'][resource]['Properties']['Policies']:
                        if 'PolicyDocument' in policy:
                            policyDocument = policy['PolicyDocument']
                            if 'Statement' in policyDocument:
                                for statement in policyDocument['Statement']:
                                    if statement['Effect'] == 'Allow':
                                        if 'iam:' in statement['Action'] or 'organizations:' in statement['Action'] or statement['Action'] == '*':
                                            result['pass'] = False
                                            result['policy1'] += 1
                                            result['errors'].append('policy1: iam namespace not allowed')

        if cfn['Resources'][resource]["Type"] == """AWS::IAM::User""":
            if "Properties" in cfn['Resources'][resource]:
                if "ManagedPolicyArns" in cfn['Resources'][resource]['Properties']:
                    for policy in cfn['Resources'][resource]['Properties']['ManagedPolicyArns']:
                        if "AWSSupportAccess" not in policy and "SupportAccess" not in policy and "CloudWatch" not in policy:
                            result['pass'] = False
                            result['policy1'] += 1
                            result['errors'].append('policy1: only Support or CloudWatch policies allowed')

        if cfn['Resources'][resource]["Type"] == """AWS::EC2::Instance""":
             if "Properties" in cfn['Resources'][resource]:
                 if "IamInstanceProfile" not in cfn['Resources'][resource]["Properties"]:
                     result['pass'] = False
                     result['policy1'] += 1
                     result['errors'].append('policy1: EC2 instance does not have IAM Policy attached')

        #Policy 2. Monitoring and Logging#
        # SUBRULE 1 Any ELB and CloudFront have to be created with logging enabled.
        if cfn['Resources'][resource]["Type"] == """AWS::ElasticLoadBalancing::LoadBalancer""":
            if "Properties" in cfn['Resources'][resource]:
                if "AccessLoggingPolicy" not in cfn['Resources'][resource]["Properties"]:
                    result['pass'] = False
                    result['policy2'] += 1
                    result['errors'].append('policy2: The resource have to be created with logging enabled')

        # SUBRULE 2 Any EC2 has to have tags for Name, Role, Owner & CostCenter
        if cfn['Resources'][resource]["Type"] == """AWS::EC2::Instance""":
            if "Properties" in cfn['Resources'][resource]:
                if "Tags" not in cfn['Resources'][resource]["Properties"]:
                    result['pass'] = False
                    result['policy2'] += 1
                    result['errors'].append('policy2: The resource have to be created with tags for Name, Role, Owner & CostCenter')

        # SUBRULE 2 Any EC2 has to have tags for Name, Role, Owner & CostCenter
        if cfn['Resources'][resource]["Type"] == """AWS::EC2::Instance""":
            if "Properties" in cfn['Resources'][resource]:
                if "Tags" in cfn['Resources'][resource]["Properties"]:
                    if "Name" not in cfn['Resources'][resource]['Properties']['Tags']:
                        result['pass'] = False
                        result['policy2'] += 1
                        result['errors'].append('policy2: The resource have to be created with tags for Name')

        if cfn['Resources'][resource]["Type"] == """AWS::EC2::Instance""":
            if "Properties" in cfn['Resources'][resource]:
                if "Tags" in cfn['Resources'][resource]["Properties"]:
                    if "Role" not in cfn['Resources'][resource]['Properties']['Tags']:
                        result['pass'] = False
                        result['policy2'] += 1
                        result['errors'].append('policy2: The resource have to be created with tags for Role')

        if cfn['Resources'][resource]["Type"] == """AWS::EC2::Instance""":
            if "Properties" in cfn['Resources'][resource]:
                if "Tags" in cfn['Resources'][resource]["Properties"]:
                    if "Owner" not in cfn['Resources'][resource]['Properties']['Tags']:
                        result['pass'] = False
                        result['policy2'] += 1
                        result['errors'].append('policy2: The resource have to be created with tags for Owner')

        if cfn['Resources'][resource]["Type"] == """AWS::EC2::Instance""":
            if "Properties" in cfn['Resources'][resource]:
                if "Tags" in cfn['Resources'][resource]["Properties"]:
                    if "CostCenter" not in cfn['Resources'][resource]['Properties']['Tags']:
                        result['pass'] = False
                        result['policy2'] += 1
                        result['errors'].append('policy2: The resource have to be created with tags for CostCenter')
    
    ########################YOUR CODE GOES ABOVE HERE########################
    # Now, how did we do? We need to return accurate statics of any policy failures.
    if not result["pass"]:
        for err in result["errors"]:
            print(err)
            send_slack(err)
        send_slack("Failed DevSecOps static code analysis. Please Fix policy breaches.", username="SecurityBotFAIL", emoji=":exclamation:")
    else:
        send_slack("Passed DevSecOps static code analysis Security Testing", username="SecurityBotPASS", emoji=":white_check_mark:")
    return result


if __name__ == "__main__":
    import sys

    result = handler(json.load(open(sys.argv[1])), None)
    print(result)