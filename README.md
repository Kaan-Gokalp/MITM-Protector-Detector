# MITM-Protector-Detector
It prevents you from being attacked by MITM techniques, also reveals attacker profile and provides counter-attack options.

# Here you can find how to use it!
usage: mitm_protector.py [-h] [-r IP_RANGE] [-g GATEWAY_IP] [-f FILTER_IP] [-s BOOLEAN]

options:
  -h, --help            Helps about commands.
  
  -r IP_RANGE, --range IP_RANGE, --iprange IP_RANGE
                        Indicate an IP range. - default: 10.0.2.1/24
                        
  -g GATEWAY_IP, --gateway GATEWAY_IP, --gatewayip GATEWAY_IP
                        Indicate your Gateway IP. - default: 10.0.2.1
                        
  -f FILTER_IP, --filter FILTER_IP
                        IPs that are pointed as safe -which will not be considered as an attacker. - default: 10.0.2.2
                        
  -s BOOLEAN, --summary BOOLEAN, --show BOOLEAN
                        Switches on/off summary (detailed info) mode. - default: True
