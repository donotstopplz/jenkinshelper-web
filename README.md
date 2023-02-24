# JenkinsHelper-Web

![](https://komarev.com/ghpvc/?username=itisokey-jenkinshelper-web&color=orange&style=flat&label=pv)

### Supports selecting multiple jobs to operate for Jenkins at the same time.
* build   
  * build with params
  * circular build if last build was failed 
  * choose last build failed jobs to build
* update
  * git branch name
  * update value of string params
  * add new string param
* error log
  * filter error log 


#### environment
* python 3.0  
##### module
  * python-jenkins     1.7.0
  * remi               2022.3.7

#### start
```shell
python jenkins_helper_main.py
```
Open the browser and type `127.0.0.1:11111` to use

![O6LLl9.png](https://s1.ax1x.com/2022/05/14/O6LLl9.png)


![O6o5dg.png](https://s1.ax1x.com/2022/05/14/O6o5dg.png)
    
