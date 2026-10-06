"use strict";

const net = require("node:net");

function isIpv4MappedAddress(address) {
  let value = address.toLowerCase();
  if (value.includes(".")) {
    const lastColon = value.lastIndexOf(":");
    if (lastColon < 0) return false;
    const octets = value.slice(lastColon + 1).split(".").map(Number);
    value = `${value.slice(0, lastColon)}:${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }
  const halves = value.split("::");
  if (halves.length > 2) return false;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const zeroCount = halves.length === 2 ? 8 - left.length - right.length : 0;
  const groups = halves.length === 2
    ? [...left, ...Array(Math.max(0, zeroCount)).fill("0"), ...right]
    : value.split(":");
  return groups.length === 8
    && groups.slice(0, 5).every((group) => Number.parseInt(group, 16) === 0)
    && Number.parseInt(groups[5], 16) === 0xffff;
}

function parseTrustedProxies(value) {
  if (value === undefined || String(value).trim() === "") return false;

  const ranges = String(value).split(",").map((entry) => entry.trim());
  if (ranges.some((entry) => !entry)) throw new Error("TRUSTED_PROXIES must contain only explicit IP addresses or CIDR ranges.");

  for (const range of ranges) {
    const [address, prefix, ...extra] = range.split("/");
    const family = net.isIP(address);
    const maxPrefix = family === 4 ? 32 : family === 6 ? 128 : -1;
    const mappedAddress = family === 6 && isIpv4MappedAddress(address);
    const minimumPrefix = family === 4 ? 8 : mappedAddress ? 104 : 32;
    if (maxPrefix < 0 || address.includes("%") || extra.length > 0) throw new Error("TRUSTED_PROXIES must contain only explicit IP addresses or CIDR ranges.");
    if (prefix !== undefined && (!/^\d+$/.test(prefix) || Number(prefix) < minimumPrefix || Number(prefix) > maxPrefix)) {
      throw new Error("TRUSTED_PROXIES must contain only explicit IP addresses or CIDR ranges.");
    }
  }

  return ranges;
}

module.exports = { parseTrustedProxies };
