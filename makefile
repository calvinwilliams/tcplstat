# 此文件由makedir.sh自动生成
############################################################
# 项目名 :
# 模块名 :
# 备 注 :
############################################################

###### 子目录配置区
DIROBJS		= \
			src \

###### 加载mktpl模板库
#@ FILESYSTEM
#@ dir_all
#@ dir_make
#@ dir_clean
#@ dir_install
#@ dir_uninstall
include $(MKTPLDIR)/makedir_$(MKTPLOS).inc

