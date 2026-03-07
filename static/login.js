(function initLoginSmsPage() {
  const sendBtn = document.querySelector("#send-sms-btn");
  const smsResultEl = document.querySelector("#login-sms-result");
  const phoneInput = document.querySelector('input[name="phone"]');
  if (!sendBtn || !smsResultEl || !phoneInput) return;

  const setSendButtonLoading = (loading, text) => {
    sendBtn.disabled = loading;
    sendBtn.textContent = text;
  };

  sendBtn.addEventListener("click", async () => {
    const phone = String(phoneInput.value || "").trim();
    if (!phone) {
      smsResultEl.textContent = "请先输入手机号。";
      smsResultEl.classList.remove("ok");
      smsResultEl.classList.add("error");
      return;
    }

    setSendButtonLoading(true, "发送中...");
    smsResultEl.textContent = "";
    smsResultEl.classList.remove("ok");
    smsResultEl.classList.remove("error");
    try {
      const resp = await fetch("/api/auth/send-sms-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone }),
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok || !data.ok) {
        const msg = data && typeof data.message === "string" && data.message ? data.message : "验证码发送失败。";
        smsResultEl.textContent = msg;
        smsResultEl.classList.remove("ok");
        smsResultEl.classList.add("error");
        return;
      }
      const remaining = typeof data.remaining === "number" ? data.remaining : null;
      smsResultEl.textContent = remaining === null ? data.message : `${data.message} 今日剩余发送次数: ${remaining}`;
      smsResultEl.classList.remove("error");
      smsResultEl.classList.add("ok");
    } catch (err) {
      smsResultEl.textContent = `验证码发送失败: ${err}`;
      smsResultEl.classList.remove("ok");
      smsResultEl.classList.add("error");
    } finally {
      setSendButtonLoading(false, "发送验证码");
    }
  });
})();
