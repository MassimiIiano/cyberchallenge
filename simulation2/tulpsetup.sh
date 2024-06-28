sudo apt-get update
sudo apt-get install software-properties-common -y
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata jq -y
sudo suricata --build-info
sudo systemctl status suricata