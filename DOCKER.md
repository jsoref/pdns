
# Use local Ubuntu mirrors
RUN sed -i 's%http://archive.ubuntu.com/ubuntu/%mirror://mirrors.ubuntu.com/mirrors.txt%' /etc/apt/sources.list

Ik weet niet of mirror: daar werkt

maar ik doe vaak dit:

ARG APT_URL=
ENV APT_URL ${APT_URL:-http://archive.ubuntu.com/ubuntu/}
RUN sed -i "s%http://archive.ubuntu.com/ubuntu/%${APT_URL}%" /etc/apt/sources.list
RUN ulimit -n 2000 && apt-get update && apt-get -y upgrade && apt-get -y clean

> maar jij zegt ‘maak het makkelijk voor mensen om een mirror dichtbij te kiezen’

Ik heb zelf APT_URL=http://tw.archive.ubuntu.com/ubuntu/ in m’n .env

# TODO

* figure out security updates (we are suddenly vendoring EVERYTHING); maybe have a docker section in secpoll? how do we make sure the user finds out?
* harden things (don't run as root)
* remove build leftovers from final image (either RUN && && && or multi-stage build)
* expose MAKEFLAGS during docker-compose build
* separate API key/webserver password/dnsdist console key
* make images land in a more sensible workdir