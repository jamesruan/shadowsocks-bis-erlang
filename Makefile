ALL: clean build
clean:
	rebar clean

build:
	rebar compile

ebin/shadowsocks.app: build

start_local: ebin/shadowsocks.app
	erl -smp auto -config ./local.config -pa ./ebin/ -boot start_sasl -s shadowsocks_app start -detached

start_server: ebin/shadowsocks.app
	erl -smp auto -config ./remote.config -pa ./ebin/ -boot start_sasl -s shadowsocks_app start -detached

test:
	ps -aux |grep beam.smp
	killall beam.smp
	make start_local start_server
	ps -aux |grep beam.smp
