#!/bin/sh
java -Dspring.profiles.active=dev -Dlogging.config=file:/Users/walker/Sources/java/spring-oauth-example/authserver/src/main/resources/logback-spring.xml  -jar build/libs/authserver-0.0.1-SNAPSHOT.jar
