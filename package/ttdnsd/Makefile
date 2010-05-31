include $(TOPDIR)/rules.mk

PKG_NAME:=ttdnsd
PKG_VERSION:=0.2
PKG_RELEASE:=1
PKG_MD5SUM:=

PKG_SOURCE_URL:=http://www.mulliner.org/collin/feed/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,TTDNSD,ttdnsd,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC=$(TARGET_CC) \
		CFLAGS="$(TARGET_CFLAGS)" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		STAGING_DIR="$(STAGING_DIR)" \
		all install
	touch $@

$(IPKG_TTDNSD):
	install -m0755 -d $(IDIR_TTDNSD)/usr/sbin
	install -m0755 -d $(IDIR_TTDNSD)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/ttdnsd $(IDIR_TTDNSD)/usr/sbin/
	$(CP) $(PKG_INSTALL_DIR)/libttdnstor.so.1 $(IDIR_TTDNSD)/usr/lib
	install -m0755 -d $(IDIR_TTDNSD)/etc
	$(CP) $(PKG_INSTALL_DIR)/ttdnsd.conf $(IDIR_TTDNSD)/etc
	$(RSTRIP) $(IDIR_TTDNSD)
	$(IPKG_BUILD) $(IDIR_TTDNSD) $(PACKAGE_DIR)

