# K5_Load_Testing

## Building Mode
# K5ExampleScaleOutv3.py
Please configure the environment setting section of this file before deploying.
The file also requires the total number of servers to be set.
Speak with your Fujitsu K5 contract owner if you need to test beyond the quotas set by default. The script was tested upto 2000 vCPU.

The script builds and configures the necessary infrastructure (security groups, keypairs, networks subnets etc) for half the server count in each K5 availability zone.

Once it starts deploying the servers, which is done in parallel queues - (using multi-threading) it also launches a routine to monitor the state of the deploying servers in the background.
When the servers are all deployed the monitoring routing will continue giving a progress update until all servers have been accounted for (deployed/errored/timed out).
Once all servers are active the monitoring script terminates and the results are logged into two files:
1. current results
2. historical results

Both of these files are then uploaded to the K5 container object specified in the initial settings.

## Destroying Mode
#
