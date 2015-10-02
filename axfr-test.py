#!/usr/bin/python
import dns.resolver
import dns.query
import dns.zone
import os
import socket

from ipwhois import IPWhois
from multiprocessing import Pool
from py2neo import neo4j

DATAPATH = "zones"

class Neo4J():
  def __init__(self, dnsname, servername):
    self.graph = neo4j.Graph()
    self.dnsname = dnsname
    self.servername = servername

    self.add_dns_node()
    self.add_server_node()
    self.create_relations()

    ipv4 = self.get_ip_from_hostname(servername)
    code = self.get_country_code(ipv4)
    self.create_country(code)
    self.create_country_relations(code)

  def add_dns_node(self):
    self.dns = neo4j.Node("DNS", name=self.dnsname)

    if not list(self.graph.find("DNS", property_key="name", property_value=self.dnsname)):
      self.graph.create(self.dns)

  def add_server_node(self):
    self.server = neo4j.Node("SERVER", name=self.servername)

    if not list(self.graph.find("SERVER", property_key="name", property_value=self.servername)):
      self.graph.create(self.server)

  def create_relations(self):

    dns = self.graph.find_one("DNS", property_key="name", property_value=self.dnsname)
    server = self.graph.find_one("SERVER", property_key="name", property_value=self.servername)

    dns_knows_server = neo4j.Relationship(dns, "KNOWS", server)
    self.graph.create(dns_knows_server)

  def create_country_relations(self, countryCode):
    server = self.graph.find_one("SERVER", property_key="name", property_value=self.servername)
    country = self.graph.find_one("COUNTRY", property_key="name", property_value=countryCode)

    self.create_relation_if_not_exists(server, country, "FROM")

  def create_country(self, countryCode):
    country = neo4j.Node("COUNTRY", name=countryCode)

    if not self.graph.find_one("COUNTRY", property_key="name", property_value=countryCode):
      self.graph.create(country)

  def get_ip_from_hostname(self, hostname):
    ipv4 = socket.gethostbyname(hostname)

    return ipv4

  def get_country_code(self, ipv4):
    obj = IPWhois(ipv4)
    results = obj.lookup()

    return results['nets'][0]['country']

  def create_relation_if_not_exists(self, start_node, end_node, relationship):
    if len(list(self.graph.match(start_node=start_node, end_node=end_node, rel_type=relationship))) > 0:
      return false
    else:
      relation = neo4j.Relationship(start_node, relationship, end_node)
      self.graph.create(relation)

def checkaxfr(domain):
  domain = domain.strip()
  try:
    ns_query = dns.resolver.query(domain,'NS')
    for ns in ns_query.rrset:
      nameserver = str(ns)[:-1]
      if nameserver is None or nameserver == "":
        continue

      if os.path.exists("." + os.sep + DATAPATH + os.sep + domain + "#" + nameserver + ".zone"):
        continue

      try:
        axfr = dns.query.xfr(nameserver, domain, lifetime=5)
        try:
          zone = dns.zone.from_xfr(axfr)
          if zone is None:
            continue
          fHandle = open("." + os.sep + DATAPATH + os.sep + domain + "#" + nameserver + ".zone", "w")
          print("Success: " + domain + " @ " + nameserver)

          Neo4J(nameserver, domain)

          for name, node in zone.nodes.items():
            rdatasets = node.rdatasets
            for rdataset in rdatasets:
              fHandle.write(str(name) + " " + str(rdataset) + "\n")
          fHandle.close()
        except Exception as e:
          continue
      except Exception as e:
        continue
  except Exception as e:
    pass
  print("Finished: " + domain)

def main():
  pool = Pool(processes=20)
  lines = open("domains.txt", "r").readlines()
  pool.map(checkaxfr, lines)
if __name__ == '__main__':
  main()
