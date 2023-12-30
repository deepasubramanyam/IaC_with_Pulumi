import boto3

def copy_ssm_parameters(source_region, destination_region):
    source_ssm = boto3.client('ssm', region_name=source_region)
    destination_ssm = boto3.client('ssm', region_name=destination_region)

    # Get all parameters from the source region
    response = source_ssm.describe_parameters()

    while True:
        for param in response['Parameters']:
            param_name = param['Name']
            param_value = source_ssm.get_parameter(Name=param_name,WithDecryption=True)['Parameter']['Value']
            param_type = param['Type']

            # Put the parameter in the destination region
            destination_ssm.put_parameter(Name=param_name, Value=param_value, Type=param_type, Overwrite=True)

            print(f"Parameter '{param_name}' copied successfully from {source_region} to {destination_region}")

        # Check if there are more parameters to fetch
        if 'NextToken' in response:
            response = source_ssm.describe_parameters(NextToken=response['NextToken'])
        else:
            break

if __name__ == "__main__":
    source_region = 'us-east-1'
    destination_region = 'us-west-2'

    copy_ssm_parameters(source_region, destination_region)