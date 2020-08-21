#
# Copyright (C) 2006 OpenWrt.org
# Copyright (C) 2006 loswillios
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=linuxigd2
PKG_VERSION:=2.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_SOURCE_URL:=@SF/linux-igd
#PKG_MD5SUM:=2c25db20a020d3a239a4e4dbf22b06db

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_BUILD_DEPENDS:=iptables libupnp

include $(INCLUDE_DIR)/package.mk

define Package/linuxigd2
  SECTION:=net
  CATEGORY:=Network
  TITLE:=UPnP daemon
  DEPENDS:=+libupnp +libpthread +dhcp-relay
  #URL:=http://linux-igd.sourceforge.net/
endef

define Package/linuxigd2/description
	It implements the UPnP Internet Gateway Device version 2
	specification (IGDv2) and allows UPnP aware clients, such
	as MSN Messenger, Azureus or Miranda to work properly from
	behind a NAT firewall.

	Please edit /etc/upnpd.conf before using upnpd!
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)  \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		BINDIR="/usr/sbin" \
		MANDIR="/usr/man" \
		HAVE_LIBIPTC=1 \
		LIBIPTC_PREFIX="$(STAGING_DIR)/usr" \
		LIBUPNP_PREFIX="$(STAGING_DIR)/usr" \
		all
endef

define Package/linuxigd2/conffiles
/etc/upnpd.conf
endef

define Package/linuxigd2/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/upnpd $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/linuxigd
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/configs/*.png $(1)/etc/linuxigd/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/configs/*.xml $(1)/etc/linuxigd/
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/configs/upnpd.conf $(1)/etc/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/configs/upnpd.init $(1)/etc/init.d/upnpd
endef

$(eval $(call BuildPackage,linuxigd2))
