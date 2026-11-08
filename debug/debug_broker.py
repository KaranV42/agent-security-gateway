# debug_broker.py
from asg.broker import CredentialBroker

def main():
    print("--- Testing Broker in Isolation ---")
    broker = CredentialBroker("secret")
    
    # 1. Issue a token
    token = broker.issue_session_token("market_data")
    print(f"1. Issued token: {token}")
    print(f"2. Internal sessions dict: {broker._sessions}")
    
    # 2. Validate with correct resource
    is_valid_correct = broker.validate_session(token, "market_data")
    print(f"3. Validate with 'market_data': {is_valid_correct}")
    
    # 3. Validate with wrong resource
    is_valid_wrong = broker.validate_session(token, "client_pii")
    print(f"4. Validate with 'client_pii': {is_valid_wrong}")

if __name__ == "__main__":
    main()