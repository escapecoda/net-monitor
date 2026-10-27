# Network Monitor

## Software Requirements Specifications (SRSs)

### Network Monitoring App

1. Network Monitoring Application
  1. Create an application that uses the configuration information in Requirement 2 to automatically check the status of servers and services.
  2. Application should run continuously using a loop until it is terminated by the user (i.e. this is not a one time check).
2. User-defined Monitoring Configuration
  1. Configure a list of servers (IP addresses or domain names) and services they want to monitor (HTTP, HTTPS, ICMP, DNS, NTP, TCP, UDP).
  2. Setting parameters for each service check, such as URL for HTTP/HTTPS, server address for DNS/NTP, port numbers for TCP/UDP, etc.
  3. Set the frequency or interval check for each service.

### Echo Server App

1. Echo Server Implementation
  1. Create and test an echo server.
  2. Create a function that can check if the echo server is functional.

### Echo Client App

1. Echo Client Implementation
  1. Create and test an echo client to work with the echo server.
