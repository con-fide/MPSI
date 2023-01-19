### Introduction
This projects aims for providing a general data analysis framework based on SGX. The crucial step in this framwork is data alignment, where we implement the private multi-party intersection for example. 

[Note] The project is mainly based on my personal interest, and is not my current main research direction. So the progress maybe very slow. Thanks for anyone's concern:)

### Installation 
+   [*SGX driver/psw/sdk*] Since our protocol is based on SGX, the tested machined must support SGX in both hardware and software stack with specific version requirements. The reader please refer the document and installer of latest software stack [here](https://gitlab.com/suifengrudao/th-psi-installation). The SGX sdk involves quite a lot during the recent several versions and many worked functions and definitions are no longer supported. For this reason, our code is not backward compatible due to this reason. 



### Local Test Command
+    Server-side: ./app  -np 2 -nm 100 -nf 10 -mod 0 -nt 1 -pn 5000 -s 2782E6B82A9824F76EAB565CF24EB000 -v
+    Client-1:    ./client.x -s 2782E6B82A9824F76EAB565CF24EB000 -i 384c7641a7494dfc8ed0b4b4c908aa67 -j 9374683ec5af45a7b0bf02d1ee12d149 -A "/home/lyj/try/sgx-ra-sample/AttestationReportSigningCACert.pem" -N 83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e -V 1 -R 0 -nt 1 -np 2 -cn 0 -h localhost -pn 5000
+    Client-2:    ./client.x -s 2782E6B82A9824F76EAB565CF24EB000 -i 384c7641a7494dfc8ed0b4b4c908aa67 -j 9374683ec5af45a7b0bf02d1ee12d149 -A "/home/lyj/try/sgx-ra-sample/AttestationReportSigningCACert.pem" -N 83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e -V 1 -R 0 -nt 1 -np 2 -cn 1 -h localhost -pn 5000