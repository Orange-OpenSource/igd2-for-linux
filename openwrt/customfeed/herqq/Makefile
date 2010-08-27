include $(TOPDIR)/rules.mk

PKG_NAME:=herqq
PKG_VERSION:=0.5.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).zip
PKG_SOURCE_URL:=http://sourceforge.net/projects/hupnp/files/hupnp/$(PKG_NAME)-$(PKG_VERSION).zip/download

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/herqq
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Herqq UPnP stack
endef
#  DEPENDS:=qt4

define Build/Configure  
        cd $(PKG_BUILD_DIR) && /home/kinnujuk/work/openwrt/backfire/build_dir/target-mipsel_uClibc-0.9.30.1/qt-everywhere-opensource-src-4.6.2/bin/qmake -spec /home/kinnujuk/work/openwrt/backfire/build_dir/target-mipsel_uClibc-0.9.30.1/qt-everywhere-opensource-src-4.6.2/mkspecs/qws/linux-openwrt-g++
endef

define Build/Compile    
        $(MAKE) -C $(PKG_BUILD_DIR)
endef

define Build/InstallDev
	mkdir -p $(1)/usr/include
	$(CP)	$(PKG_BUILD_DIR)/hupnp/include/* \
		$(1)/usr/include/
	mkdir -p $(1)/usr/lib
	$(CP)	$(PKG_BUILD_DIR)/hupnp/bin/libHUpnp* \
		$(1)/usr/lib/
	$(CP)	$(PKG_BUILD_DIR)/hupnp/bin/libQtSolutions_SOAP* \
		$(1)/usr/lib/
endef

define Package/herqq/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hupnp/bin/libHUpnp.so.1.0.0 $(1)/usr/lib/
	$(LN) libHUpnp.so.1.0.0 $(1)/usr/lib/libHUpnp.so.1.0
	$(LN) libHUpnp.so.1.0.0 $(1)/usr/lib/libHUpnp.so.1
	$(LN) libHUpnp.so.1.0.0 $(1)/usr/lib/libHUpnp.so
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hupnp/bin/libQtSolutions_SOAP-2.7.so.1.0.0 $(1)/usr/lib/
	$(LN) libQtSolutions_SOAP-2.7.so.1.0.0 $(1)/usr/lib/libQtSolutions_SOAP-2.7.so.1.0
	$(LN) libQtSolutions_SOAP-2.7.so.1.0.0 $(1)/usr/lib/libQtSolutions_SOAP-2.7.so.1
	$(LN) libQtSolutions_SOAP-2.7.so.1.0.0 $(1)/usr/lib/libQtSolutions_SOAP-2.7.so
endef

#define Package/herqq/install
#	$(INSTALL_DIR) $(1)/usr/lib
#	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hupnp/bin/libHUpnp* $(1)/usr/lib/
#	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hupnp/bin/libQtSolutions_SOAP* $(1)/usr/lib/
#endef

$(eval $(call BuildPackage,herqq))
