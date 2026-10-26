function isObj(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function clean(obj) {
  if (!isObj(obj) || !("data" in obj)) return false;

  let changed = false;
  const data = obj.data;

  // 1. 营销弹窗
  if (Array.isArray(data)) {
    const bad = {
      marketAd: 1,
      financeRecommendPopup: 1,
      activityAppUsageScene: 1,
      newAttributionPopup: 1,
      attributionPopup: 1,
      newChannelAttrPopup: 1
    };
    const kept = data.filter(function (item) {
      if (!isObj(item)) return true;
      const t = item.popupWindowType;
      return !t || !bad[t];
    });
    if (kept.length !== data.length) {
      obj.data = kept;
      changed = true;
    }
  }

  // 2. 信息流 / 瀑布流
  if (isObj(data)) {
    // feeds
    if (Array.isArray(data.list) && data.list.length > 0) {
      data.list = [];
      if ("hasMore" in data) data.hasMore = false;
      changed = true;
    }
    // waterfall
    if (Array.isArray(data.materialList) && data.materialList.length > 0) {
      data.materialList = [];
      if ("needRequest" in data) data.needRequest = false;
      changed = true;
    }
    // moduleList 里的 feeds / waterfall
    if (Array.isArray(data.moduleList)) {
      const before = data.moduleList.length;
      data.moduleList = data.moduleList.filter(function (m) {
        if (!isObj(m) || typeof m.moduleKey !== "string") return true;
        return (
          m.moduleKey !== "homepage_feeds_module" &&
          m.moduleKey !== "homepage_waterfall_module"
        );
      });
      if (data.moduleList.length !== before) changed = true;
    }
    // 广告 creative
    if (Array.isArray(data.adm)) {
      for (let i = 0; i < data.adm.length; i++) {
        const ad = data.adm[i];
        if (!isObj(ad)) continue;
        if (Array.isArray(ad.creative) && ad.creative.length) {
          ad.creative = [];
          changed = true;
        }
        if (Array.isArray(ad.backupCreative) && ad.backupCreative.length) {
          ad.backupCreative = [];
          changed = true;
        }
      }
    }
  }

  return changed;
}

(function () {
  const res = typeof $response === "object" && $response ? $response : null;
  if (!res || typeof res.body !== "string" || !res.body) {
    $done({});
    return;
  }

  // 只处理较小的明文包，避免拖慢
  if (res.body.length > 2 * 1024 * 1024) {
    $done({});
    return;
  }

  const body = res.body.trim();
  // 只碰明文 JSON，加密包直接放行
  if (body.charAt(0) !== "{" && body.charAt(0) !== "[") {
    $done({});
    return;
  }

  let obj;
  try {
    obj = JSON.parse(body);
  } catch (e) {
    $done({});
    return;
  }

  if (!clean(obj)) {
    $done({});
    return;
  }

  $done({ body: JSON.stringify(obj) });
})();
