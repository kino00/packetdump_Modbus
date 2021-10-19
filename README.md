# packetdump_Modbus

次のgithubのコードを参考に、handle_modbus_tcp関数とhandle_modbus関数を
追加してModbusパケットを解析できるようにした。
https://github.com/libpnet/libpnet/blob/master/examples/packetdump.rs

今回、対象としているのはModbus/TCPであるため、handle_tcp_packet関数の中に、
送信元、送信先のポート番号が502番であり、payloadがある場合にModbusパケットの
解析を行なっている。

test_dataのファイルの中のpcapファイルをTcpReplayを用いて再送することで動作確認を
行なった。
