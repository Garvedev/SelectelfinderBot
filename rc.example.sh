#!/bin/bash

[[ "$BASH_SOURCE" == "$0" ]] && {
    echo "Please 'source' this script, don't execute it directly"
    echo "e.g.:"
    echo "$ source $0"
    return 1 2> /dev/null || exit 1
}

export OS_AUTH_URL="https://cloud.api.selcloud.ru/identity/v3"
export OS_IDENTITY_API_VERSION="3"
export OS_VOLUME_API_VERSION="3"
export OS_COMPUTE_API_VERSION="2.72"

export CLIFF_FIT_WIDTH=1

export OS_PROJECT_DOMAIN_NAME='PROJECT_DOMAIN'
export OS_PROJECT_ID='PROJECT_ID'
export OS_TENANT_ID='PROJECT_ID'
export OS_REGION_NAME='ru-1'

export OS_USER_DOMAIN_NAME='USER_DOMAIN'
export OS_USERNAME='USERNAME'

echo "Please enter your OpenStack Password: "
read -sr OS_PASSWORD_INPUT
export OS_PASSWORD=$OS_PASSWORD_INPUT
