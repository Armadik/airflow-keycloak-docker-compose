
# API

AIRFLOW__API__AUTH_BACKENDS: 'user_auth'

```bash
export CLIENT_ID="airflow"
export CLIENT_SECRET="EIhxJQW2U4DIOEMHHMtKyWVBrpbj20DK"
export USERNAME="airflow"
export PASSWORD="airflow"
TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "client_secret=${CLIENT_SECRET}" \
  --data-urlencode "username=${USERNAME}" \
  --data-urlencode "password=${PASSWORD}" | jq -r '.access_token')
curl -s -X GET -H "application/json" -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/v1/dags
```