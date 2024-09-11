import base64
import chardet
import cbor2
import json
import os
import pprint
import requests
import sys

def test_call_parameters(method: str, payload: dict, headers: dict):
    r = requests.post(f'{prot}://httpbin.org/{method}', data=payload, headers=headers)
    print(r.json())


# Initialize transaction endpoint
def init_transaction() -> tuple[str, str]:
    with open('auth_request.json') as f:
        auth_request = json.load(f)
    r = requests.post(f'{prot}://{host}:{port}/ui/presentations', json=auth_request, verify=ssl_verify)
    # r = requests.post(f'{prot}://{host}:{port}/ui/presentations', json=auth_request, verify='../grnet_cert.pem')
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
    r = requests.get(f'{prot}://{host}:{port}/wallet/request.jwt/{transaction_id}', verify=ssl_verify)
    print(f'#2. Get auth request returned (status={r.status_code}).')
    print('  Authorization request payload as a signed JWT:')
    auth_request_payload = r.text
    print(auth_request_payload)
    print()


# Get presentation definition
def get_presentation_def(transaction_d: str) -> None:
    r = requests.get(f'{prot}://{host}:{port}/wallet/pd/{transaction_id}', verify=ssl_verify)
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

    if vp_token_valid:
        with open("mdoc_kotlin_status_list_valid.cbor", "rb") as f:
            dumped_mdoc = f.read()
    else:
        with open("mdoc_kotlin_status_list_revoked.cbor", "rb") as f:
            dumped_mdoc = f.read()
    the_encoding = chardet.detect(dumped_mdoc)['encoding']
    print(f'Dumped mdoc: {dumped_mdoc}, encoding: {the_encoding}')

    urlencoded_mdoc = base64.urlsafe_b64encode(dumped_mdoc)
    print(f'Urlencoded mdoc: {urlencoded_mdoc}')
    payload = {'state': transaction_id,
               'vp_token': urlencoded_mdoc,
               'presentation_submission': json.dumps(wallet_response)
               }

    # test_call_parameters('post', payload, headers)
    r = requests.post(f'{prot}://{host}:{port}/wallet/direct_post', data=payload, headers=headers, verify=ssl_verify)
    print(f'Send wallet response returned (status={r.status_code}):')
    if (r.status_code != 200):
        print(r)
        exit(1)
    r_json = r.json()
    pprint.pprint(r_json, compact=True)
    redirect_uri = r_json['redirect_uri']
    response_code = redirect_uri.split('response_code=')[-1]
    print(f'response_code: {response_code}')
    print()

    return response_code


# Get wallet response
def get_wallet_response(presentation_id: str, response_code: str) -> None:
    r = requests.get(f'{prot}://{host}:{port}/ui/presentations/{presentation_id}?response_code={response_code}', verify=ssl_verify)
    print(f'#5. Get wallet response returned (status={r.status_code}).')
    wallet_response = r.json()
    pprint.pprint(wallet_response)
    print()


# Get presentation event log
def get_presentation_event_log(presentation_id: str) -> None:
    r = requests.get(f'{prot}://{host}:{port}/ui/presentations/{presentation_id}/events', verify=ssl_verify)
    print(f'#6. Get presentation event log returned (status={r.status_code}).')
    presentation_events = r.json()
    pprint.pprint(presentation_events)
    print()


def check_revocation():
    headers = {'X-Api-Key': '305a4915-32b8-4ea4-ba5f-b1a867cd6728'}
    r = requests.post(f'https://issuer-openid4vc.ssi.tir.budru.de/status-list/api/lsp-hackathon/new-reference', headers=headers)
    uri_index = r.json()
    print(f'New status response: {uri_index}')

    headers = {'Content-type': 'application/json',
               'Accept': 'application/json'
               }
    payload = {'uri': uri_index['uri'],
               'index': uri_index['index'],
               }
    print(f'POST uri={uri_index["uri"]}, index={uri_index["index"]}')
    r = requests.post(f'http://{host}:{port}/ui/presentations/0/revoked', json=payload, headers=headers)
    print(f'Send revocation check request returned (status={r.status_code}): {r.json()}')




host = 'localhost'
port = '8080'
ssl_verify = False
prot = 'http'
if ssl_verify:
    prot = 'https'
vp_token_valid = True


if __name__ == '__main__':
    try:
        host = sys.argv[1]
        port = sys.argv[2]
        ssl_verify = sys.argv[3] == 'True'
        vp_token_valid = sys.argv[4] == 'True'
    except IndexError:
        pass
    print(f'Host: {host}')
    print(f'Port: {port}')
    print(f'ssl_verify: {ssl_verify}')
    print(f'protocol: {prot}')
    print(f'vp_token_valid: {vp_token_valid}')


    # check_revocation()
    # exit(1)

    transaction_id, presentation_id = init_transaction()
    get_auth_request(transaction_id)
    get_presentation_def(transaction_id)
    response_code = send_wallet_response(transaction_id)
    get_wallet_response(presentation_id, response_code)
    get_presentation_event_log(presentation_id)
