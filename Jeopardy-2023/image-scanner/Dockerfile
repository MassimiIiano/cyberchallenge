FROM ubuntu:20.04

RUN apt update
RUN apt upgrade -y
RUN apt autoremove

COPY flag_instructions.txt .

RUN head -n -1 flag_instructions.txt > temp
RUN mv temp flag_instructions.txt

RUN ls -al
RUN echo "The flag is stored in a secret place"

CMD sleep 1000