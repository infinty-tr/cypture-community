
import { existsSync } from "node:fs";

const COOLDOWN_MS = 30_000;
const STUCK_LIMIT = 5;
const FRESH_HOURS = 4;
const STALL_SECONDS = 600;

const managed = new Map();
const state = new Map();

export const LoopEnforcer = async ({ client, $, directory }) => {
  const sh = $.cwd(directory).nothrow();

  const disabled = () => {
    try { return existsSync(directory + "/.cypture/plugin/ENFORCER_OFF"); } catch { return false; }
  };

  return {
    "chat.message": async (input) => {
      try {
        const a = String(input?.agent ?? "").toLowerCase();
        if (input?.sessionID && a.includes("cypture")) managed.set(input.sessionID, true);
      } catch {  }
    },

    event: async ({ event }) => {
      try {
        if (disabled()) return;
        if (event?.type !== "session.idle") return;
        const sessionID = event.properties?.sessionID;
        if (!sessionID) return;

        if (!managed.has(sessionID)) return;

        try {
          const s = await client.session.get({ path: { id: sessionID } });
          if ((s?.data ?? s)?.parentID) return;
        } catch {  }

        let SURF = "";
        try {
          const r = await sh`cat ${directory + "/.cypture/plugin/ACTIVE_TARGET"}`;
          SURF = (r?.stdout?.toString?.() ?? "").trim().split("\n")[0].trim();
        } catch {  }
        if (!SURF) return;
        try {
          const r = await sh`test -f ${SURF} && echo ok`;
          if (!(r?.stdout?.toString?.() ?? "").includes("ok")) return;
        } catch { return; }

        try {
          const r = await sh`find ${SURF} -newermt ${"-" + FRESH_HOURS + " hours"}`;
          if (!(r?.stdout?.toString?.() ?? "").trim()) return;
        } catch {  }

        let out = "";
        try {
          const r = await sh`bash ${directory + "/scripts/decide_next.sh"} ${SURF}`;
          out = (r?.stdout?.toString?.() ?? "") + (r?.stderr?.toString?.() ?? "");
        } catch { return; }
        const line = (out.match(/^DECISION:.*$/m) ?? [""])[0].trim();
        if (!line) return;

        const now = Date.now();
        const prev = state.get(sessionID) ?? { lastInject: 0, lastSig: "", stuck: 0, stopped: false };

        if (/^DECISION:\s*STOP/.test(line)) {
          if (prev.stopped) return;
          state.set(sessionID, { ...prev, lastInject: now, stopped: true });
          const reason = (line.match(/reason=(\S+)/) ?? [, "?"])[1];
          await client.session
            .prompt({ path: { id: sessionID }, body: { parts: [{ type: "text",
              text: "🛑 [DÖNGÜ SÜRÜCÜSÜ] decide_next.sh = " + line + "\n\n" +
                (reason === "VULN_FOUND_AND_EXHAUSTED"
                  ? "Doğrulanmış açık VAR ve yüzey kanıtla tükendi → reporter-agent'ı çağır, FİNAL RAPOR üret."
                  : reason === "EXHAUSTED_NO_VULN"
                  ? "Yüzey KANITLA tükendi (her host × her uygulanabilir sınıf × L3+, 0 doğrulanmış bulgu). Dürüst kapanış raporu üret — 'açık yok' YALNIZCA burada geçerli."
                  : reason === "BUDGET_EXHAUSTED"
                  ? "İstek bütçesi doldu (run.budget_max). Şu ana kadarki KANITLI durumu raporla, operatöre bütçe artışı gerekip gerekmediğini söyle."
                  : reason === "UNREACHABLE"
                  ? "Hedefe ulaşılamıyor (kapsam-dışı/erişilemez). Net şekilde operatöre bildir."
                  : "Dur. Sebebi operatöre net bildir.") +
                "\n(Bu DUR kararı script'ten geldi; otomatik dürtme bu oturum için durduruldu.)" }] } })
            .catch(() => {});
          return;
        }

        if (now - prev.lastInject < COOLDOWN_MS) return;
        const sig = line.replace(/next=\S+/, "").replace(/\(.*?\)/g, "").trim();
        const stuck = (sig === prev.lastSig) ? prev.stuck + 1 : 0;

        if (stuck >= STUCK_LIMIT) {
          state.set(sessionID, { lastInject: now, lastSig: sig, stuck: 0, stopped: false });
          await client.session
            .prompt({ path: { id: sessionID }, body: { parts: [{ type: "text",
              text: "⚠️ [DÖNGÜ SÜRÜCÜSÜ] " + STUCK_LIMIT + " turdur AYNI karar tekrarlıyor:\n" + line +
                "\nGerçekten ajan spawn edip biten host/sınıf için mark_tested.sh / mark_class.sh çağırıyor musun? " +
                "Sahte ilerleme yapma. Takıldıysan engeli operatöre net söyle. (Otomatik dürtme bu tur durduruldu.)" }] } })
            .catch(() => {});
          return;
        }

        state.set(sessionID, { lastInject: now, lastSig: sig, stuck, stopped: false });

        await client.session
          .prompt({ path: { id: sessionID }, body: { parts: [{ type: "text",
            text:
              "🔁 [DÖNGÜ SÜRÜCÜSÜ — OTOMATİK DEVAM] İŞ BİTMEDİ — rapor/durma/bekleme YOK. Tek beyin kararı:\n\n" +
              line +
              "\n\nŞİMDİ, BU TURDA:\n" +
              "1. Biten ajanların host'larını İŞARETLE: `mark_tested.sh <surf> <host> <derinlik>` + kapanan sınıf için `mark_class.sh`.\n" +
              "   (Spawn'da KİRALA: `assign_agent.sh <surf> <task_id> <host...>`. Model HATASI görürsen: `model_health.sh <surf> <model> down` + `model_pick.sh` ile sıradakiyle respawn.)\n" +
              "2. Dalga sonu TEK ÇAĞRI: `bash scripts/wave_finalize.sh <surf> <cyp_json>` — sinyal topla/oob/audit/derinlik/bütçe/yay/zincir + DECISION basar.\n" +
              "3. DECISION'a göre AKSİYON: NEW-HOST→'next=' host'ları task() spawn · DEEPEN(signal)→audit · DEEPEN(class/depth)→ajana ver L3+ · NEW-HYPOTHESIS→`next_hypothesis.sh` · CANCEL:/RESPAWN:→`background_cancel`+model_pick ile yeniden spawn.\n" +
              "4. OUT-OF-SCOPE host'lara ASLA ajan açma. KALAN bitene kadar döngü sürer.\n" +
              "(Bu mesaj erken 'bitti' diyemeyesin diye harness tarafından OTOMATİK gönderildi.)" }] } })
          .catch(() => {});
      } catch {  }
    },
  };
};
