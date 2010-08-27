# 
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=libwpsutil
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
#PKG_SOURCE_URL:=
#PKG_MD5SUM:=8918dcf7428cd119d0c8275765ff2833

include $(INCLUDE_DIR)/package.mk

define Package/libwpsutil/Default
  SECTION:=libs
  CATEGORY:=Libraries
  URL:=???
endef

define Package/libwpsutil
  $(call Package/libwpsutil/Default)
  DEPENDS:=+libgcrypt
  TITLE:=WPS util library
  MENU:=1
endef

define Package/libwpsutil/description
	The WPS util library implements Wi-Fi Protected Setup state machine
	and it is used to create WPS registration protocol messages.    
endef

define Build/Configure
	$(call Build/Configure/Default, \
		--enable-shared \
		--enable-static \
	);
endef

TARGET_CFLAGS += $(FPIC)

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib \
			-Wl,-rpath-link,$(STAGING_DIR)/usr/lib -lgcrypt" \
		CCOPT="$(TARGET_CFLAGS)" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
endef

define Build/InstallDev
	mkdir -p $(1)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/wpsutil $(1)/usr/include/
	mkdir -p $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libwpsutil.{a,so*} $(1)/usr/lib/
	mkdir -p $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/libwpsutil.pc $(1)/usr/lib/pkgconfig/
endef

define Package/libwpsutil/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libwpsutil.so.* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libwpsutil))
