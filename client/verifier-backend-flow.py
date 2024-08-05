import json
import pprint
import requests


def test_call_parameters(method: str, payload: dict, headers: dict):
    r = requests.post(f'https://httpbin.org/{method}', data=payload, headers=headers)
    print(r.json())


# Initialize transaction endpoint
def init_transaction() -> tuple[str, str]:
    with open('auth_request.json') as f:
        auth_request = json.load(f)
    r = requests.post('http://localhost:8080/ui/presentations', json=auth_request)
    r_json = r.json()
    print(f'#1. Auth request returned (status={r.status_code}):')
    pprint.pprint(r_json, compact=True)

    # request_id would be a more accurate parameter name than transaction_id.
    transaction_id = r_json['request_uri'].split('/')[-1]
    presentation_id = r_json['presentation_id']
    print(f'presentation_id: {presentation_id}')
    print(f'transaction_id: {transaction_id}')
    print()

    return transaction_id, presentation_id


# Get authorization request
def get_auth_request(transaction_id: str) -> None:
    r = requests.get(f'http://localhost:8080/wallet/request.jwt/{transaction_id}')
    print(f'#2. Get auth request returned (status={r.status_code}).')
    print('  Authorization request payload as a signed JWT:')
    auth_request_payload = r.text
    print(auth_request_payload)
    print()


# Get presentation definition
def get_presentation_def(transaction_d: str) -> None:
    r = requests.get(f'http://localhost:8080/wallet/pd/{transaction_id}')
    print(f'#3. Get presentation definition returned (status={r.status_code}).')
    print('  Presentation definition of the authorization request as JSON:')
    presentation_def = r.json()
    pprint.pprint(presentation_def, compact=True)
    print()


# Send wallet response
def send_wallet_response(transaction_id: str) -> str:
    print('#4. Send the following wallet response.')
    with open('wallet_response.json') as f:
        wallet_response = json.load(f)
    pprint.pprint(wallet_response, compact=True)
    headers = {'Content-type': 'application/x-www-form-urlencoded',
               'Accept': 'application/json'
               }
    payload = {'state': transaction_id,
               'vp_token': json.dumps({'id': '123456'}),
               'presentation_submission': json.dumps(wallet_response)
               }

    # test_call_parameters('post', payload, headers)
    r = requests.post('http://localhost:8080/wallet/direct_post', data=payload, headers=headers)
    print(f'Send wallet response returned (status={r.status_code}):')
    r_json = r.json()
    pprint.pprint(r_json, compact=True)
    redirect_uri = r_json['redirect_uri']
    response_code = redirect_uri.split('response_code=')[-1]
    print(f'response_code: {response_code}')
    print()

    return response_code


# Get wallet response
def get_wallet_response(presentation_id: str, response_code: str) -> None:
    r = requests.get(f'http://localhost:8080/ui/presentations/{presentation_id}?response_code={response_code}')
    print(f'#5. Get wallet response returned (status={r.status_code}).')
    wallet_response = r.json()
    pprint.pprint(wallet_response)
    print()


# Get presentation event log
def get_presentation_event_log(presentation_id: str) -> None:
    r = requests.get(f'http://localhost:8080/ui/presentations/{presentation_id}/events')
    print(f'#6. Get presentation event log returned (status={r.status_code}).')
    presentation_events = r.json()
    pprint.pprint(presentation_events)
    print()


if __name__ == '__main__':
    transaction_id, presentation_id = init_transaction()
    get_auth_request(transaction_id)
    get_presentation_def(transaction_id)
    response_code = send_wallet_response(transaction_id)
    get_wallet_response(presentation_id, response_code)
    get_presentation_event_log(presentation_id)
