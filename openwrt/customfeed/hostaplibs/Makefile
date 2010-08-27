# 
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=hostaplibs
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
#PKG_SOURCE_URL:=
#PKG_MD5SUM:=8918dcf7428cd119d0c8275765ff2833

include $(INCLUDE_DIR)/package.mk

define Package/hostaplibs/Default
  SECTION:=libs
  CATEGORY:=Libraries
  URL:=???
endef

define Package/hostaplibs
  $(call Package/hostaplibs/Default)
  DEPENDS:=+libgcrypt
  TITLE:=Provides WPS functionality
  MENU:=1
endef

define Package/hostaplibs/description
	The wpa_supplicant and hostapd libraries implement Wi-Fi Protected Setup state machines
	and they are used to create WPS registration protocol messages.
endef

define Build/Configure
	$(call Build/Configure/Default, \
		--enable-shared \
		--enable-static \
	);
endef

TARGET_CPPFLAGS := \
	-fPIC \
	-I$(STAGING_DIR)/usr/include/libnl-tiny \
	-I$(PKG_BUILD_DIR)/src/crypto \
	$(TARGET_CPPFLAGS) \
	-I$(STAGING_DIR)/usr/include/madwifi \
	-I$(STAGING_DIR)/usr/include/mac80211 \
	-DCONFIG_LIBNL20 \
	-D_GNU_SOURCE

#TARGET_LDFLAGS += -lgcrypt -lgpg-error

define Build/Compile
        CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS)" \
        $(MAKE) -C $(PKG_BUILD_DIR)/wpa_supplicant \
                $(TARGET_CONFIGURE_OPTS) \
                $(DRIVER_MAKEOPTS) \
                LDFLAGS="-L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib \
			-Wl,-rpath-link,$(STAGING_DIR)/usr/lib -lgcrypt" \
                all libwpa_supplicant.so
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR)/wpa_supplicant \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		PREFIX="/usr" \
		install_libwpa_supplicant
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/hostap
	$(CP) $(PKG_INSTALL_DIR)/usr/include/hostap/wpa_supplicant_iface.h $(1)/usr/include/hostap
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libwpa_supplicant.so* $(1)/usr/lib/
#	mkdir -p $(1)/usr/lib/pkgconfig
#	$(CP) $(PKG_BUILD_DIR)/usr/lib/pkgconfig/libwpa_supplicant.pc $(1)/usr/lib/pkgconfig/
endef

define Package/hostaplibs/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libwpa_supplicant.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,hostaplibs))
