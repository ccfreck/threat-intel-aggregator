import ipaddress

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def main():
    print(is_valid_ip("8.8.8.8"))

if __name__ == "__main__":
    main()

