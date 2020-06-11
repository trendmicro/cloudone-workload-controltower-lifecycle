# Cloud One Workload Security Control Tower lifecycle implementation guide

[Cloud One Workload Security] helps to detect and protect against malware, exploitation of vulnerabilities, and unauthorized 
changes to your Windows and Linux systems as well as containers. 

[Cloud One Workload Security]: https://cloudone.trendmicro.com

This guide provides details on how to integrate provisioning of Workload Security with [AWS Control Tower] to ensure 
that every account added through Control Tower Account Factory is automatically provisioned in Workload Security, 
providing centralized visibility to the security posture of ec2 instances deployed in each account as well as the 
foundation for policy and billing automation. This solution can be leveraged to manage AWS account provisioning for 
customer managed instances of Deep Security Software as well. See the 
[Deep Security Software](#Deep Security Software Deployments) section for additional guidance.

[AWS Control Tower]:https://aws.amazon.com/controltower/


## Overview

The Lifecycle Hook solution provides a cloudformation template which, when launched in the Control Tower Master Account, 
deploys AWS infrastructure to ensure Workload Security monitors each Account Factory AWS account automatically. The 
solution consists of 2 lambda functions; one to manage our role and access Workload Security, and another to manage the 
lifecycle of the first lambda. AWS Secrets Manager is leveraged to store the API key for Workload in the Master account 
and a CloudWatch Events rule is configured to trigger the customization lambda when a Control Tower account is 
successfully deployed.

### Usage

You will first need to [generate an API key for Workload Security]. Once you've created the API key, log into the 
Control Tower master account and [launch the lifecycle template]. Select the AWS region for your Control Tower 
deployment before entering the Workload ApiKey and completing the launch stack wizard. On the last page of the wizard, 
be sure to select the checkbox to acknowledge that this template may create IAM resources. Once the stack is complete, 
work with application teams to automate [agent installation] and activate protection.

[generate an API key for Workload Security]:https://aws.amazon.com/controltower/
[launch the lifecycle template]:https://us-east-1.console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=https://s3.amazonaws.com/trend-micro-cloud-one-workload-controltower-lifecycle/Trend-Micro-Workload-LifeCycle.yaml&stackName=WorkloadLifeCycleHook
[agent installation]:https://help.deepsecurity.trendmicro.com/agent-install.html

### Implementation

During stack launch, the lifecycle lambda will be executed for each existing Control Tower Account, including the 
Control Tower Master, Audit, and Log accounts. After launch,, a cloudwatch event rule will trigger the lifecycle lambda 
for each successful Control Tower CreateManagedAccount event. The lifecycle lambda function will retrieve the Workload 
ApiKey from AWS Secrets Manager, then get the External ID for your organization from the Workload API. Next the lambda 
function will assume the ControlTowerExecution role in the target Managed Account in order to create the necessary cross 
account role and associated policy. Finally, a call will be made to the Workload API to add this Managed Account to your  
Workload Security tenant.

### Upgrade

As new capabilities are added to Workload Security, it may be necessary on occasion to update the permissions for the 
application's cross account role. To update the role deployed by the lifecycle hook, update the Workload stack with the 
latest template which can be found at its original url. The parameter values should not be modified from their original 
values unless directed by Trend Micro Support. Updating the cloudformation stack will update the role used by all existing 
accounts and the role created for future enrollments. 

[original url]:https://s3.amazonaws.com/trend-micro-cloud-one-workload-controltower-lifecycle/Trend-Micro-Workload-LifeCycle.yaml

### Removal

To remove the lifecycle hook, identify and delete the cloudformation stack. Protection for Managed Accounts which  
have already been added will remain in place. For details on removing an AWS account from Workload Security see 
the help documentation.


[removing an account subscriptio]:https://www.cloudWorkload.com/help/organisation/subscriptions.html


### Deep Security Software Deployments

Some organizations may choose to host the Deep Security Software which manages agent policy and protection into their 
own AWS account instead of using the hosted solution. This product is available in a pay as you go or bring your own 
license model from the [AWS Marketplace]. Trend Micro recommends deploying the [Deep Security Quickstart] into your 
Control Tower Security account and either leveraging a public facing ELB in the quickstart deployment, or configuring 
[AWS PrivateLink] to create connectivity between workloads Managed Accounts and the Deep Security Manager console.

[AWS Marketplace]:https://aws.amazon.com/marketplace/pp/Trend-Micro-Trend-Micro-Deep-Security/B01AVYHVHO
[Deep Security Quickstart]:https://s3.amazonaws.com/awsmp-fulfillment-cf-templates-prod/d70fb77f-c90c-40e9-8cba-2d257a7b01d2.a79962c7-5e92-42f7-6484-e9ed7afcd8f6.template
[AWS PrivateLink]:https://aws.amazon.com/privatelink/