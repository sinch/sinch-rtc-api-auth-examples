SHELL := bash
.SUFFIXES:
.PHONY: clean test docs format
.DEFAULT_GOAL := test

clean:
	./gradlew clean

test:
	./gradlew test

docs:
	./gradlew javaDoc

format:
	find . -type f -name '*.java' -exec google-java-format -i {} \;
