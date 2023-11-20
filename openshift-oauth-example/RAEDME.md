## OpenShift oauth proxy RayCluster example
This is a minimal example to secure the RayCluster Dashboard url with the OpenShift Oauth Proxy. By default the Dashboard is http, therefore the network traffic is not encrypted. It's also not secured and accessible to everyone. The example adds access control mechanism to the dashboard for users who has the right access using service account token.

### Prerequisites
- OpenShift Cluster
- [Install KubeRay Operator](https://github.com/ray-project/kuberay#helm-charts)

### Example:
This will create a RayCluster with the Oauth Proxy SideCart in the RayCluster head pod along with secrets and service account objects. The requests to the dashboard will be directed to the OpenShift login page.
```shell
oc apply -f raycluster-jobtest-oauth.yaml
```
This should create the following pod:
```
jobtest-head-gtkx6                         2/2     Running   0              56s
jobtest-worker-small-group-jobtest-h25xb   1/1     Running   0              56s
jobtest-worker-small-group-jobtest-mkc99   1/1     Running   0              56s
kuberay-operator-5d64d88fdb-twq9q          1/1     Running   0              3d18h
```
and Routes:
```
NAME                    HOST/PORT                                        PATH   SERVICES        PORT          TERMINATION            WILDCARD
jobtest-ingress-qkmdx   ray-dashboard-jobtest-default.apps.crc.testing          jobtest-oauth   oauth-proxy   passthrough/Redirect   None
jobtest-oauth-proxy     jobtest-oauth-proxy-default.apps-crc.testing            jobtest-oauth   <all>         reencrypt              None
```

The dashboard url also serves as Ray api endpoint for the JobSubmissionClient python SDk. For example, we can connect to the RayCluster using the example
```python
from ray.job_submission import JobSubmissionClient
client = JobSubmissionClient("https://ray-dashboard-jobtest-default.apps.crc.testing", verify=False, headers={"Authorization":"Bearer sha256~kp3yg44clTWuzI0dTnhU5LEoN_eE7KSJwHh6ouVImQM"})
client.list_jobs()
[]
```
where the `Bearer <token>` can be obtained with `oc whoami --show-token`.

