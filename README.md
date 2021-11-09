# packetdump_Modbus

次のgithubのコードを参考に、Modbusパケットを解析できるようにした。
https://github.com/libpnet/libpnet/blob/master/examples/packetdump.rs

https://github.com/libpnet/libpnet/blob/master/docs/using_packet.md
上のURLのYour Own Projectの項目に沿った形でModbusTCPを解析する様に作成を改修した。
502番ボートが送信元か送信先に含まれている場合に、ModbusTCPの解析を行い、
ファンクションコードの種類と送信元パケットか送信先パケットのどちらであるのかによって
処理を行なっている。

test_dataのファイルの中のpcapファイルをTcpReplayを用いて再送することで動作確認を
行なった。


