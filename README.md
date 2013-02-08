verify_uk_la
============

##2013-02-08
发现可能需要使用 RSA_blinding_on 功能才能避免 RSA_Verify 的函数验证出错。
这个需要编写个程序来验证一下。

要使用临时变量来处理i2d_RSAPrivateKey()。




