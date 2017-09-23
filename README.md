# 國立東華大學–資訊安全管理–RSA+HASH數位簽章
由Java語言撰寫，Client端傳送訊息到Server，會將訊息全文以RSA加密並將訊息經MD5雜湊函數後Output一同傳送至Server端
<br>Server端將會對加密內容進行解密並在進行一次HASH，將此值與傳來的值進行比較，若相同代表內容未被竄改。
<br>2017/9/24
