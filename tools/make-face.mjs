// Builds a stylised 3D head (vertex-coloured) as a GLB: node tools/make-face.mjs public/face.glb
import fs from "node:fs";
import path from "node:path";

const out = process.argv[2] || "public/face.glb";
const LAT = 120, LON = 160;
const pos = [], col = [], idx = [];
const g = (x, c, s) => Math.exp(-((x - c) ** 2) / (2 * s * s));

for (let i = 0; i <= LAT; i++) {
  const v = i / LAT; // 0 top .. 1 bottom
  const th = v * Math.PI;
  for (let j = 0; j <= LON; j++) {
    const u = j / LON;
    const ph = u * 2 * Math.PI; // 0 = front (+z)
    let x = Math.sin(th) * Math.sin(ph), y = Math.cos(th), z = Math.sin(th) * Math.cos(ph);
    // base head proportions: narrower width, taller, deeper
    let sx = 0.78, sy = 1.0, sz = 0.92;
    // jaw: broad, square lower face (y < -0.3), taper at chin
    if (y < -0.2) { const t = (-0.2 - y) / 0.8; sx *= 1 - 0.35 * t * t; sz *= 1 - 0.15 * t; }
    // cranium slightly wider at temples
    sx *= 1 + 0.05 * g(y, 0.35, 0.2);
    let X = x * sx, Y = y * sy * 1.12, Z = z * sz;
    const front = Math.max(0, z); // facing amount
    const fx = x, fy = y;
    // nose (ridge + tip)
    Z += 0.22 * front * g(fx, 0, 0.07) * g(fy, -0.08, 0.16) + 0.08 * front * g(fx, 0, 0.09) * g(fy, -0.25, 0.06);
    // brow ridge
    Z += 0.06 * front * g(fy, 0.22, 0.05) * (g(fx, -0.28, 0.16) + g(fx, 0.28, 0.16));
    // eye sockets
    Z -= 0.07 * front * g(fy, 0.1, 0.06) * (g(fx, -0.3, 0.09) + g(fx, 0.3, 0.09));
    // cheekbones
    Z += 0.04 * front * g(fy, -0.05, 0.1) * (g(fx, -0.45, 0.12) + g(fx, 0.45, 0.12));
    // lips and chin
    Z += 0.05 * front * g(fx, 0, 0.18) * g(fy, -0.45, 0.05) + 0.07 * front * g(fx, 0, 0.2) * g(fy, -0.72, 0.08);
    Z -= 0.03 * front * g(fx, 0, 0.2) * g(fy, -0.55, 0.03);
    // ears
    const side = Math.abs(x) * (1 - front);
    const ear = 0.13 * g(Math.abs(x), 1, 0.08) * g(fy, 0.0, 0.14) * g(z, -0.05, 0.25);
    X += Math.sign(x) * ear;
    pos.push(X, Y, Z);
    // colours: skin, grey hair on top/back, darker brows, lips
    let c = [0.86, 0.68, 0.58];
    const hair = y > 0.42 - 0.35 * Math.max(0, -z) && !(z > 0.55 && y < 0.62);
    if (hair && y > -0.1) c = [0.62, 0.6, 0.58];
    if (front > 0.6 && g(fy, 0.2, 0.025) * (g(fx, -0.28, 0.12) + g(fx, 0.28, 0.12)) > 0.5) c = [0.42, 0.38, 0.35];
    if (front > 0.6 && g(fy, 0.1, 0.03) * (g(fx, -0.3, 0.05) + g(fx, 0.3, 0.05)) > 0.5) c = [0.3, 0.32, 0.36];
    if (front > 0.7 && g(fx, 0, 0.13) * g(fy, -0.46, 0.025) > 0.5) c = [0.72, 0.45, 0.42];
    col.push(...c);
    void side;
  }
}
for (let i = 0; i < LAT; i++)
  for (let j = 0; j < LON; j++) {
    const a = i * (LON + 1) + j, b = a + LON + 1;
    idx.push(a, b, a + 1, a + 1, b, b + 1);
  }

// smooth normals
const nrm = new Float32Array(pos.length);
for (let k = 0; k < idx.length; k += 3) {
  const [a, b, c] = [idx[k] * 3, idx[k + 1] * 3, idx[k + 2] * 3];
  const ux = pos[b] - pos[a], uy = pos[b + 1] - pos[a + 1], uz = pos[b + 2] - pos[a + 2];
  const vx = pos[c] - pos[a], vy = pos[c + 1] - pos[a + 1], vz = pos[c + 2] - pos[a + 2];
  const nx = uy * vz - uz * vy, ny = uz * vx - ux * vz, nz = ux * vy - uy * vx;
  for (const p of [a, b, c]) { nrm[p] += nx; nrm[p + 1] += ny; nrm[p + 2] += nz; }
}
for (let p = 0; p < nrm.length; p += 3) {
  const l = Math.hypot(nrm[p], nrm[p + 1], nrm[p + 2]) || 1;
  // sphere winding gives inward normals; flip outward
  nrm[p] /= -l; nrm[p + 1] /= -l; nrm[p + 2] /= -l;
}
// flip winding to match outward normals
for (let k = 0; k < idx.length; k += 3) [idx[k + 1], idx[k + 2]] = [idx[k + 2], idx[k + 1]];

const P = new Float32Array(pos), C = new Float32Array(col), I = new Uint32Array(idx);
const min = [Infinity, Infinity, Infinity], max = [-Infinity, -Infinity, -Infinity];
for (let p = 0; p < P.length; p += 3) for (let a = 0; a < 3; a++) { min[a] = Math.min(min[a], P[p + a]); max[a] = Math.max(max[a], P[p + a]); }

const bufs = [P, nrm, C, I].map((a) => Buffer.from(a.buffer));
let off = 0;
const views = bufs.map((b, i) => { const v = { buffer: 0, byteOffset: off, byteLength: b.length, target: i === 3 ? 34963 : 34962 }; off += b.length; return v; });
const bin = Buffer.concat(bufs);
const n = P.length / 3;
const gltf = {
  asset: { version: "2.0", generator: "tds-ga3 make-face" },
  scene: 0,
  scenes: [{ nodes: [0] }],
  nodes: [{ mesh: 0, name: "Head" }],
  meshes: [{ name: "Head", primitives: [{ attributes: { POSITION: 0, NORMAL: 1, COLOR_0: 2 }, indices: 3, material: 0 }] }],
  materials: [{ name: "Skin", pbrMetallicRoughness: { baseColorFactor: [1, 1, 1, 1], metallicFactor: 0, roughnessFactor: 0.7 } }],
  buffers: [{ byteLength: bin.length }],
  bufferViews: views,
  accessors: [
    { bufferView: 0, componentType: 5126, count: n, type: "VEC3", min, max },
    { bufferView: 1, componentType: 5126, count: n, type: "VEC3" },
    { bufferView: 2, componentType: 5126, count: n, type: "VEC3" },
    { bufferView: 3, componentType: 5125, count: I.length, type: "SCALAR" },
  ],
};
let js = Buffer.from(JSON.stringify(gltf));
js = Buffer.concat([js, Buffer.alloc((4 - (js.length % 4)) % 4, 0x20)]);
const binP = Buffer.concat([bin, Buffer.alloc((4 - (bin.length % 4)) % 4)]);
const hdr = Buffer.alloc(12);
hdr.write("glTF", 0); hdr.writeUInt32LE(2, 4); hdr.writeUInt32LE(12 + 8 + js.length + 8 + binP.length, 8);
const ch = (len, type) => { const b = Buffer.alloc(8); b.writeUInt32LE(len, 0); b.write(type, 4); return b; };
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, Buffer.concat([hdr, ch(js.length, "JSON"), js, ch(binP.length, "BIN\0"), binP]));
console.log(out, fs.statSync(out).size, "bytes");
