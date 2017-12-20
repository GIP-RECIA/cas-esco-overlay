FROM tomcat:8.5

ARG USER_ID=1000
ARG GROUP_ID=1000

ADD tomcat-users.xml /usr/local/tomcat/conf/
RUN sed -E -i 's/allow=".+"/allow="^.*$"/g' /usr/local/tomcat/webapps/manager/META-INF/context.xml
RUN sed -E -i 's/port="8080"/port="11080"/g' /usr/local/tomcat/conf/server.xml

# Fix permissions to match host user
RUN groupadd -g ${GROUP_ID:-1000} tomcat
RUN useradd -u ${USER_ID:-1000} -g ${GROUP_ID:-1000} tomcat
RUN chown -R tomcat:tomcat /usr/local/tomcat

USER tomcat