class Server:

    mac = None
    ip = None
    port = None

    def __init__(self, mac, ip, port):
        self.mac = mac
        self.ip = ip
        self.port = port


class Network:

    lb_mac = None
    lb_ip = None

    servers = []
    servers_num = None

    def __init__(self):
        self.lb_mac = '00:00:00:00:aa:0a'
        self.lb_ip = '10.8.10.99'

        self.alt_servers_chosen = False

        if self.alt_servers_chosen:

            # alternative servers
            self.servers = [
                Server("90:1b:0e:48:f2:7b", self.lb_ip, 1),
                Server("90:1b:0e:05:9c:67", self.lb_ip, 3),
                Server("90:1b:0e:48:f1:97", self.lb_ip, 5)
            ]


        else:

            # pi servers
            self.servers = [
                Server("b8:27:eb:d5:72:15", self.lb_ip, 1),
                Server("b8:27:eb:a4:71:a1", self.lb_ip, 3),
                Server("b8:27:eb:02:ea:80", self.lb_ip, 5)
            ]

        self.servers_num = len(self.servers)