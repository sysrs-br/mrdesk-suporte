const API = "/api";
let token = localStorage.getItem("mrdesk_token");
let nomeUsuario = localStorage.getItem("mrdesk_nome");
// Item 41: só admin entra no painel. usuarioSuper = superadmin (cria os admins
// das empresas); senão é o admin de uma empresa (cria os técnicos dele).
let usuarioAdmin = localStorage.getItem("mrdesk_admin") === "1";
let usuarioSuper = localStorage.getItem("mrdesk_super") === "1";
// Conta da Sysrs: só ela tem Versão MR1, Licença MR1 e "Liberar nova máquina";
// os gráficos do servidor são dela e do superadmin.
let usuarioSysrs = localStorage.getItem("mrdesk_sysrs") === "1";
let dispositivos = [];
let catalogos = [];
let catalogoAtual = null;
let idParaMover = null;
let usuarios = [];
let tecnicos = [];

const ICONE_ARQUIVOS = '<svg class="icon" viewBox="0 0 24 24"><path d="M4 8h13M13 5l4 3-4 3"/><path d="M20 16H7M11 13l-4 3 4 3"/></svg>';
const ICONE_CONECTAR = '<svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M8 12h7M12 9l3 3-3 3"/></svg>';
const ICONE_PONTOS = '<svg class="icon" viewBox="0 0 24 24" style="stroke-width:2.5;"><circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/></svg>';
const ICONE_CATALOGO = '<svg class="icon" viewBox="0 0 24 24"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>';
const ICONE_EDITAR = '<svg class="icon" viewBox="0 0 24 24"><path d="M11 5H6a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-5"/><path d="M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4z"/></svg>';
const ICONE_REMOVER = '<svg class="icon" viewBox="0 0 24 24"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M10 11v6M14 11v6"/></svg>';
const ICONE_EMAIL = '<svg class="icon" viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/></svg>';
const ICONE_MOVER = '<svg class="icon" viewBox="0 0 24 24"><path d="M4 20h9"/><path d="M4 4h6v6H4z"/><path d="M15 7h6M18 4l3 3-3 3"/></svg>';

// Botão de mostrar/ocultar em todo campo de senha (login, criar senha, alterar senha)
const ICONE_OLHO = '<svg class="icon" viewBox="0 0 24 24"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>';
const ICONE_OLHO_FECHADO = '<svg class="icon" viewBox="0 0 24 24"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/><path d="M4 4l16 16"/></svg>';
document.querySelectorAll('input[type="password"]').forEach(campo => {
  const caixa = document.createElement("span");
  caixa.className = "campo-senha";
  campo.parentNode.insertBefore(caixa, campo);
  caixa.appendChild(campo);
  const olho = document.createElement("button");
  olho.type = "button";
  olho.className = "olho-senha";
  olho.tabIndex = -1;
  olho.title = "Mostrar a senha";
  olho.innerHTML = ICONE_OLHO;
  olho.addEventListener("click", () => {
    const mostrar = campo.type === "password";
    campo.type = mostrar ? "text" : "password";
    olho.innerHTML = mostrar ? ICONE_OLHO_FECHADO : ICONE_OLHO;
    olho.title = mostrar ? "Ocultar a senha" : "Mostrar a senha";
  });
  caixa.appendChild(olho);
  // Formulário limpo (modal reaberto): a senha volta a ficar oculta
  if (campo.form) campo.form.addEventListener("reset", () => {
    campo.type = "password";
    olho.innerHTML = ICONE_OLHO;
    olho.title = "Mostrar a senha";
  });
});

// Login renovado pelo servidor enquanto o painel e usado (vale 7 dias sem uso):
// toda resposta pode trazer um token novo no cabecalho X-Novo-Token.
const fetchOriginal = window.fetch.bind(window);
window.fetch = async (...args) => {
  const resp = await fetchOriginal(...args);
  try {
    const novo = resp.headers.get("X-Novo-Token");
    if (novo && token) {
      token = novo;
      localStorage.setItem("mrdesk_token", novo);
    }
  } catch (e) { /* ignora */ }
  return resp;
};

function headersAuth() {
  return { "Authorization": "Bearer " + token, "Content-Type": "application/json" };
}

function formatarId(id) {
  if (!id) return "";
  const digitos = String(id).replace(/\D/g, "");
  const partes = [];
  let i = digitos.length;
  while (i > 0) {
    const inicio = Math.max(0, i - 3);
    partes.unshift(digitos.slice(inicio, i));
    i = inicio;
  }
  return partes.join(" ");
}

function formatarDataHora(str) {
  if (!str) return "—";
  const m = str.match(/(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/);
  if (!m) return str;
  return `${m[3]}/${m[2]}/${m[1]} ${m[4]}:${m[5]}:${m[6]}`;
}

function calcularTempoDecorrido(str, online) {
  if (!str || online) return "";
  const m = str.match(/(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/);
  if (!m) return "";
  const data = new Date(m[1], m[2] - 1, m[3], m[4], m[5], m[6]);
  const diffMs = Date.now() - data.getTime();
  if (diffMs < 0) return "";
  const diffMin = Math.floor(diffMs / 60000);
  if (diffMin < 60) return "";
  const diffHoras = Math.floor(diffMin / 60);
  if (diffHoras < 24) {
    const minutosRestantes = diffMin % 60;
    return `há ${diffHoras}h ${minutosRestantes}min`;
  }
  const dias = Math.floor(diffHoras / 24);
  const horasRestantes = diffHoras % 24;
  return `há ${dias} dia${dias > 1 ? "s" : ""} ${horasRestantes}h`;
}

// Item 16: "Inativo há X" (verde, itálico) quando ninguem mexe no teclado/mouse ha 3 min ou mais
const SEM_USO_A_PARTIR_DE_SEGUNDOS = 180;
function textoSemUso(segundos) {
  if (segundos === null || segundos === undefined || segundos < SEM_USO_A_PARTIR_DE_SEGUNDOS) return "";
  const min = Math.floor(segundos / 60);
  if (min < 60) return `Inativo há ${min} min`;
  const horas = Math.floor(min / 60);
  if (horas < 24) return `Inativo há ${horas}h ${min % 60}min`;
  const dias = Math.floor(horas / 24);
  return `Inativo há ${dias} dia${dias > 1 ? "s" : ""} ${horas % 24}h`;
}

// Versão do ERP (item 30). Compara número por número entre os pontos
// (1.10 é maior que 1.9). Devolve -1, 0 ou 1; partes que faltam valem 0.
function compararVersoes(a, b) {
  const pa = String(a).split(".").map(n => parseInt(n, 10) || 0);
  const pb = String(b).split(".").map(n => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
function versaoValida(v) {
  return /^\d+(\.\d+)*$/.test(v);
}
// Versão mínima: guardada neste navegador (engrenagem ao lado do usuário).
const CHAVE_VERSAO_MINIMA = "mrdesk_versao_minima_erp";
function lerVersaoMinima() {
  try { return localStorage.getItem(CHAVE_VERSAO_MINIMA) || ""; } catch (_) { return ""; }
}
function versaoAbaixoDaMinima(versao) {
  const minima = lerVersaoMinima();
  if (!versao || !minima || !versaoValida(versao) || !versaoValida(minima)) return false;
  return compararVersoes(versao, minima) < 0;
}

// Coluna Sistema (01/10): o MRDesk manda "windows / Windows 10 Pro - 10.0.19045";
// na coluna mostra so "Windows 10 Pro"; o hint traz o resto.
function sistemaCurto(sistema) {
  if (!sistema) return "—";
  let s = sistema;
  const barra = s.indexOf(" / ");
  if (barra >= 0) s = s.slice(barra + 3);
  const traco = s.lastIndexOf(" - ");
  if (traco > 0) s = s.slice(0, traco);
  return s.trim() || sistema;
}
// MRDesk desatualizado (04/10): o servidor manda a versão de cada máquina e
// a versão publicada; máquina com versão anterior ganha um ícone antes do
// sistema, com a versão instalada na dica. O nome da coluna mostra quantas são.
let versaoPublicada = null;
const ICONE_DESATUALIZADO = '<svg class="icon" viewBox="0 0 24 24"><path d="M21 12a9 9 0 0 1-15.5 6.2"/><path d="M3 12a9 9 0 0 1 15.5-6.2"/><path d="M18.5 2v4h-4"/><path d="M5.5 22v-4h4"/></svg>';
function iconeDesatualizado(d) {
  if (!d.desatualizado) return "";
  // sem versão = máquina que não deu sinal desde que o painel passou a guardar a versão
  const dica = (d.versao ? `MRDesk desatualizado: versão ${d.versao} instalada` : "MRDesk desatualizado: versão não informada, a máquina ainda não deu sinal")
    + (versaoPublicada ? ` (atual: ${versaoPublicada})` : "");
  return `<span title="${escapeHtml(dica)}">${ICONE_DESATUALIZADO}</span>`;
}
function atualizarDicaDeDesatualizados() {
  const th = document.getElementById("th-desatualizado");
  const n = dispositivos.filter(d => d.desatualizado).length;
  th.classList.toggle("tem-desatualizado", n > 0);
  th.title = (n === 0 ? "Nenhum dispositivo com MRDesk desatualizado"
    : n === 1 ? "1 dispositivo com MRDesk desatualizado" : `${n} dispositivos com MRDesk desatualizado`)
    + (versaoPublicada ? ` (versão atual: ${versaoPublicada})` : "");
}

function hintSistema(d) {
  const linhas = [];
  if (d.sistema) linhas.push(`Sistema: ${d.sistema}`);
  if (d.versao) linhas.push(`MRDesk: ${d.versao}`);
  if (d.memoria) linhas.push(`Memória: ${d.memoria}`);
  if (d.processador) linhas.push(`Processador: ${d.processador}`);
  if (d.computador) linhas.push(`Computador: ${d.computador}`);
  return linhas.length ? linhas.join("\n") : "Sem informações (chegam no próximo registro do MRDesk)";
}

function mostrarApp() {
  document.getElementById("tela-login").style.display = "none";
  document.getElementById("app").style.display = "flex";
  document.getElementById("nome-usuario").textContent = nomeUsuario;
  document.getElementById("btn-gerenciar-usuarios").style.display = usuarioAdmin ? "flex" : "none";
  document.getElementById("rotulo-gerenciar-usuarios").textContent = usuarioSuper ? "Gerenciar contas" : "Gerenciar usuários";
  // Técnicos autorizados e exclusão de dispositivo: só o admin da empresa (não o superadmin)
  document.getElementById("btn-tecnicos-autorizados").style.display = (usuarioAdmin && !usuarioSuper) ? "flex" : "none";
  document.getElementById("separador-menu-usuario").style.display = usuarioAdmin ? "block" : "none";
  document.getElementById("btn-menu-excluir-dispositivo").style.display = (usuarioAdmin && !usuarioSuper) ? "flex" : "none";
  // Item 9 e 30: liberar nova máquina e Licença MR1 - só a conta da Sysrs
  document.getElementById("btn-menu-liberar-maquina").style.display = usuarioSysrs ? "flex" : "none";
  document.getElementById("btn-menu-licenca").style.display = usuarioSysrs ? "flex" : "none";
  // Item 41: o superadmin não tem conta (vê só a lista "sem conta"); Versão
  // MR1 e engrenagem só na Sysrs; gráficos do servidor só Sysrs e superadmin.
  const app = document.getElementById("app");
  app.classList.toggle("modo-super", usuarioSuper);
  app.classList.toggle("sem-mr1", !usuarioSysrs);
  document.getElementById("busca").placeholder = usuarioSysrs
    ? "Buscar por cliente, apelido, ID ou versão MR1" : "Buscar por cliente, apelido ou ID";
  app.classList.toggle("sem-graficos", !(usuarioSysrs || usuarioSuper));
  document.getElementById("area-sem-conta").style.display = usuarioSuper ? "flex" : "none";
  if (usuarioSuper) {
    carregarSemConta();
  } else {
    carregarCatalogos();
  }
  if (usuarioSysrs || usuarioSuper) carregarTrafego();
}

// ---- Gráficos do cabeçalho: tráfego de saída (limite de 10 TB/mês do plano
// da Oracle), espaço em disco da VM e sessões que passaram pelo relay ----
let timerTrafego = null;

function formatarPct(pct) {
  return pct.toLocaleString("pt-BR", { maximumFractionDigits: 2 });
}

function formatarMB(bytes) {
  // Mesma unidade do "free -m" (MiB); usado na pizza da memoria (VM tem pouca memoria)
  return Math.round(bytes / 1024 ** 2).toLocaleString("pt-BR");
}
function formatarGB(bytes) {
  // Mesma unidade do "df -h" (GiB), pra bater com o que aparece no servidor.
  return (bytes / 1024 ** 3).toLocaleString("pt-BR", { maximumFractionDigits: 1 });
}

// limites: { vermelho, amarelo } = a partir de quantos % a pizza muda de cor
// (padrão, 02/10: amarela acima de 60%, vermelha acima de 70%; false = nunca muda).
async function atualizarPizza(idElemento, rota, montarHint, limites = { amarelo: 60.01, vermelho: 70.01 }) {
  const el = document.getElementById(idElemento);
  try {
    const resp = await fetch(`${API}/${rota}`, { headers: headersAuth() });
    if (resp.status === 401) return;
    const data = await resp.json();
    if (data.success) {
      const pct = Math.min(100, Math.max(0, Number(data.percentual) || 0));
      el.style.setProperty("--pct", pct);
      const vermelha = !!limites && limites.vermelho !== undefined && pct >= limites.vermelho;
      const amarela = !vermelha && !!limites && limites.amarelo !== undefined && pct >= limites.amarelo;
      el.classList.toggle("alerta", vermelha);
      el.classList.toggle("aviso", amarela);
      el.title = montarHint(pct, data);
      el.style.display = "block";
    } else {
      el.style.display = "none";
    }
  } catch (err) {
    el.style.display = "none";
  }
}

async function carregarTrafego() {
  clearTimeout(timerTrafego);
  await Promise.all([
    atualizarPizza("grafico-trafego", "trafego",
      (pct, d) => `${formatarPct(pct)}% já utilizado do tráfego de saída de 10Tb no mês (${formatarGB(d.saida_bytes)}Gb usados)`),
    atualizarPizza("grafico-disco", "disco",
      (pct, d) => `${formatarPct(pct)}% já utilizado do disco de ${formatarGB(d.total_bytes)}Gb (${formatarGB(d.usado_bytes)}Gb usados)`),
    atualizarPizza("grafico-memoria", "memoria",
      (pct, d) => `${formatarPct(pct)}% já utilizado da memória de ${formatarMB(d.total_bytes)}Mb (${formatarMB(d.usado_bytes)}Mb usados)`),
    atualizarPizza("grafico-relay", "relay",
      (pct, d) => {
        // Período: últimos 30 dias, ou desde a primeira conexão auditada se
        // a auditoria tiver menos de 30 dias.
        let periodo = "dos últimos 30 dias";
        if (d.desde) {
          const desde = new Date(d.desde);
          if (Date.now() - desde.getTime() < 29.5 * 24 * 60 * 60 * 1000) {
            const pad = (n) => String(n).padStart(2, "0");
            periodo = `desde ${pad(desde.getDate())}/${pad(desde.getMonth() + 1)}`;
          }
        }
        return d.total
          ? `${formatarPct(pct)}% das sessões ${periodo} passaram pelo relay (${d.relay} de ${d.total})`
          : `Nenhuma sessão ${periodo} (relay)`;
      },
      false),
  ]);
  // Atualiza a cada 5 minutos enquanto a tela estiver aberta.
  timerTrafego = setTimeout(() => { if (token) carregarTrafego(); }, 5 * 60 * 1000);
}

// Cartões da tela de login: "form-login", "form-esqueci" ou "form-definir-senha"
function mostrarCartaoLogin(id) {
  ["form-login", "form-esqueci", "form-definir-senha"].forEach(f => {
    document.getElementById(f).style.display = f === id ? "block" : "none";
  });
}

function mostrarLogin() {
  document.getElementById("tela-login").style.display = "flex";
  document.getElementById("app").style.display = "none";
  mostrarCartaoLogin("form-login");
  // Reforca a limpeza mesmo se o navegador tentar autopreencher a senha
  // salva (autofill do proprio gerenciador de senhas) ao carregar a tela.
  document.getElementById("login-senha").value = "";
}

const filtroAtivosSalvo = localStorage.getItem("mrdesk_filtro_ativos");
const filtroServidorSalvo = localStorage.getItem("mrdesk_filtro_servidor");
const filtroInstaladoSalvo = localStorage.getItem("mrdesk_filtro_instalado");
if (filtroAtivosSalvo !== null) {
  document.getElementById("check-ativos").checked = filtroAtivosSalvo === "1";
}
if (filtroServidorSalvo !== null) {
  document.getElementById("check-servidor").checked = filtroServidorSalvo === "1";
}
if (filtroInstaladoSalvo !== null) {
  document.getElementById("check-instalado").checked = filtroInstaladoSalvo === "1";
}

// Link de senha recebido por e-mail: https://.../?senha=<código>
const codigoLinkSenha = new URLSearchParams(location.search).get("senha");
if (codigoLinkSenha) {
  abrirDefinirSenha();
} else if (new URLSearchParams(location.search).has("esqueci")) {
  // Veio do link "Esqueci minha senha" do MRDeskPro: abre direto na página de pedir o link
  mostrarLogin();
  mostrarCartaoLogin("form-esqueci");
} else if (token) { mostrarApp(); } else { mostrarLogin(); }

// ---- Criar/redefinir a senha pelo link do e-mail (item 41) ----
function msgLogin(id, texto, tipo) {
  const el = document.getElementById(id);
  el.textContent = texto || "";
  el.className = "msg-login" + (texto ? " " + tipo : "");
}

async function abrirDefinirSenha() {
  document.getElementById("tela-login").style.display = "flex";
  document.getElementById("app").style.display = "none";
  mostrarCartaoLogin("form-definir-senha");
  const texto = document.getElementById("texto-definir-senha");
  try {
    const resp = await fetch(`${API}/senha/link?t=${encodeURIComponent(codigoLinkSenha)}`);
    const data = await resp.json();
    if (data.success) {
      texto.textContent = `${data.nome}, crie a senha do login ${data.email}.`;
      document.getElementById("campos-definir-senha").style.display = "block";
    } else {
      texto.textContent = "";
      msgLogin("msg-definir-senha", data.error || "Link inválido.", "erro");
    }
  } catch (err) {
    texto.textContent = "";
    msgLogin("msg-definir-senha", "Não foi possível conectar ao servidor.", "erro");
  }
}

function senhaForaDaRegra(senha) {
  if (senha.length < 8) return "A senha deve ter pelo menos 8 caracteres.";
  if (!/[A-Za-z]/.test(senha) || !/[0-9]/.test(senha)) return "A senha deve ter pelo menos uma letra e um número.";
  return null;
}

document.getElementById("form-definir-senha").addEventListener("submit", async (e) => {
  e.preventDefault();
  const senha = document.getElementById("definir-senha-nova").value;
  const confirmar = document.getElementById("definir-senha-confirmar").value;
  if (senha !== confirmar) { msgLogin("msg-definir-senha", "A senha e a confirmação não conferem.", "erro"); return; }
  const fora = senhaForaDaRegra(senha);
  if (fora) { msgLogin("msg-definir-senha", fora, "erro"); return; }
  const btn = document.getElementById("btn-definir-senha");
  btn.disabled = true;
  try {
    const resp = await fetch(`${API}/senha/definir`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ t: codigoLinkSenha, senha })
    });
    const data = await resp.json();
    if (data.success) {
      document.getElementById("campos-definir-senha").style.display = "none";
      document.getElementById("texto-definir-senha").textContent = "";
      msgLogin("msg-definir-senha", data.admin
        ? "Senha criada. Entre no painel com o seu e-mail e a senha nova."
        : "Senha criada. Entre no MRDeskPro com o seu e-mail e a senha nova.", "ok");
      document.getElementById("link-definir-voltar").style.display = data.admin ? "block" : "none";
      if (data.admin && data.email) localStorage.setItem("mrdesk_ultimo_usuario", data.email);
    } else {
      msgLogin("msg-definir-senha", data.error || "Não foi possível salvar a senha.", "erro");
    }
  } catch (err) {
    msgLogin("msg-definir-senha", "Não foi possível conectar ao servidor.", "erro");
  } finally {
    btn.disabled = false;
  }
});

// Sai do link (tira o código do endereço) e vai pro login
document.getElementById("link-definir-voltar").addEventListener("click", (e) => {
  e.preventDefault();
  location.href = location.pathname;
});

// ---- Esqueci minha senha (item 41) ----
document.getElementById("link-esqueci-senha").addEventListener("click", (e) => {
  e.preventDefault();
  msgLogin("msg-esqueci", "", "");
  document.getElementById("esqueci-email").value = document.getElementById("login-usuario").value.trim();
  mostrarCartaoLogin("form-esqueci");
});
document.getElementById("link-voltar-login").addEventListener("click", (e) => {
  e.preventDefault();
  mostrarCartaoLogin("form-login");
});
document.getElementById("form-esqueci").addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("esqueci-email").value.trim();
  const btn = document.getElementById("btn-esqueci");
  btn.disabled = true;
  try {
    await fetch(`${API}/senha/esqueci`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email })
    });
    // Mesma mensagem exista o e-mail ou não (o servidor não revela quem tem cadastro)
    msgLogin("msg-esqueci", "Se este e-mail estiver cadastrado, enviamos o link. Confira a caixa de entrada e o spam.", "ok");
  } catch (err) {
    msgLogin("msg-esqueci", "Não foi possível conectar ao servidor.", "erro");
  } finally {
    btn.disabled = false;
  }
});

const usuarioSalvo = localStorage.getItem("mrdesk_ultimo_usuario");
if (usuarioSalvo) {
  document.getElementById("login-usuario").value = usuarioSalvo;
}

document.getElementById("form-login").addEventListener("submit", async (e) => {
  e.preventDefault();
  const usuario = document.getElementById("login-usuario").value.trim();
  const senha = document.getElementById("login-senha").value;
  const erroEl = document.getElementById("erro-login");
  const btn = document.getElementById("btn-entrar");
  const spinner = document.getElementById("spinner-entrar");
  const texto = document.getElementById("texto-btn-entrar");
  erroEl.style.display = "none";

  btn.disabled = true;
  spinner.style.display = "inline-block";
  texto.textContent = "Entrando...";

  try {
    const resp = await fetch(API + "/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: usuario, password: senha })
    });
    const data = await resp.json();
    if (data.success) {
      token = data.token;
      nomeUsuario = data.name;
      usuarioAdmin = !!data.admin;
      usuarioSuper = !!data.super;
      usuarioSysrs = !!data.sysrs;
      localStorage.setItem("mrdesk_sysrs", usuarioSysrs ? "1" : "0");
      localStorage.setItem("mrdesk_token", token);
      localStorage.setItem("mrdesk_nome", nomeUsuario);
      localStorage.setItem("mrdesk_admin", usuarioAdmin ? "1" : "0");
      localStorage.setItem("mrdesk_super", usuarioSuper ? "1" : "0");
      localStorage.removeItem("mrdesk_excluir_device");
      localStorage.setItem("mrdesk_ultimo_usuario", usuario);
      mostrarApp();
    } else {
      erroEl.textContent = data.error || "E-mail ou senha inválidos.";
      erroEl.style.display = "block";
    }
  } catch (err) {
    erroEl.textContent = "Não foi possível conectar ao servidor.";
    erroEl.style.display = "block";
  } finally {
    btn.disabled = false;
    spinner.style.display = "none";
    texto.textContent = "Entrar";
  }
});

function sair() {
  localStorage.removeItem("mrdesk_token");
  // a busca guardada pro F5 não passa pra quem entrar depois
  try { sessionStorage.removeItem("mrdesk_grupo_busca"); } catch (e) { /* ignora */ }
  document.getElementById("busca").value = "";
  localStorage.removeItem("mrdesk_nome");
  localStorage.removeItem("mrdesk_admin");
  localStorage.removeItem("mrdesk_super");
  localStorage.removeItem("mrdesk_sysrs");
  token = null;
  document.getElementById("login-senha").value = "";
  mostrarLogin();
}

document.getElementById("btn-usuario-menu").addEventListener("click", (e) => {
  e.stopPropagation();
  document.getElementById("menu-usuario-lista").classList.toggle("aberto");
});

document.getElementById("btn-sair-menu").addEventListener("click", () => {
  document.getElementById("menu-usuario-lista").classList.remove("aberto");
  sair();
});

document.getElementById("btn-gerenciar-usuarios").addEventListener("click", () => {
  document.getElementById("menu-usuario-lista").classList.remove("aberto");
  abrirModalUsuarios();
});

document.getElementById("btn-tecnicos-autorizados").addEventListener("click", () => {
  document.getElementById("menu-usuario-lista").classList.remove("aberto");
  abrirModalTecnicos();
});

document.getElementById("btn-alterar-senha").addEventListener("click", () => {
  document.getElementById("menu-usuario-lista").classList.remove("aberto");
  abrirModalAlterarSenha();
});

// ---- Configurações deste navegador (engrenagem): versão mínima do ERP ----
document.getElementById("btn-configuracoes").addEventListener("click", () => {
  document.getElementById("erro-configuracoes").style.display = "none";
  document.getElementById("config-versao-minima").value = lerVersaoMinima();
  document.getElementById("overlay-configuracoes").style.display = "flex";
  document.getElementById("config-versao-minima").focus();
});
function fecharModalConfiguracoes() {
  document.getElementById("overlay-configuracoes").style.display = "none";
}
document.getElementById("btn-cancelar-configuracoes").addEventListener("click", fecharModalConfiguracoes);
document.getElementById("form-configuracoes").addEventListener("submit", (e) => {
  e.preventDefault();
  const valor = document.getElementById("config-versao-minima").value.trim();
  const erroEl = document.getElementById("erro-configuracoes");
  if (valor && !versaoValida(valor)) {
    erroEl.textContent = "Use só números separados por ponto (ex.: 21.8.0.1).";
    erroEl.style.display = "block";
    return;
  }
  try {
    if (valor) localStorage.setItem(CHAVE_VERSAO_MINIMA, valor);
    else localStorage.removeItem(CHAVE_VERSAO_MINIMA);
  } catch (_) {
    erroEl.textContent = "Este navegador não permitiu guardar a configuração.";
    erroEl.style.display = "block";
    return;
  }
  fecharModalConfiguracoes();
  renderizarTabela();
});

function abrirModalAlterarSenha() {
  document.getElementById("erro-alterar-senha").style.display = "none";
  document.getElementById("form-alterar-senha").reset();
  document.getElementById("overlay-alterar-senha").style.display = "flex";
}

function fecharModalAlterarSenha() {
  document.getElementById("overlay-alterar-senha").style.display = "none";
}
document.getElementById("btn-cancelar-alterar-senha").addEventListener("click", fecharModalAlterarSenha);

document.getElementById("form-alterar-senha").addEventListener("submit", async (e) => {
  e.preventDefault();
  const senhaAtual = document.getElementById("senha-atual").value;
  const senhaNova = document.getElementById("senha-nova").value;
  const senhaNovaConfirmar = document.getElementById("senha-nova-confirmar").value;
  const erroEl = document.getElementById("erro-alterar-senha");
  erroEl.style.display = "none";

  if (senhaNova !== senhaNovaConfirmar) {
    erroEl.textContent = "A nova senha e a confirmação não conferem.";
    erroEl.style.display = "block";
    return;
  }

  const fora = senhaForaDaRegra(senhaNova);
  if (fora) {
    erroEl.textContent = fora;
    erroEl.style.display = "block";
    return;
  }

  try {
    const resp = await fetch(`${API}/usuarios/senha`, {
      method: "PUT", headers: headersAuth(),
      body: JSON.stringify({ senha_atual: senhaAtual, nova_senha: senhaNova })
    });
    const data = await resp.json();
    if (data.success) {
      // As outras sessões caíram; esta continua com o token novo.
      if (data.token) {
        token = data.token;
        localStorage.setItem("mrdesk_token", token);
      }
      fecharModalAlterarSenha();
      alert("Senha alterada com sucesso. As outras sessões abertas foram encerradas.");
    } else {
      erroEl.textContent = data.error || "Erro ao alterar senha.";
      erroEl.style.display = "block";
    }
  } catch (err) {
    erroEl.textContent = "Erro de conexão: " + err.message;
    erroEl.style.display = "block";
  }
});

async function carregarCatalogos() {
  try {
    const resp = await fetch(`${API}/catalogos`, { headers: headersAuth() });
    if (resp.status === 401) { mostrarLogin(); return; }
    const data = await resp.json();
    catalogos = data.catalogos || [];
    // Mantem o catalogo selecionado, mas com os dados atualizados (ex.: depois de editar)
    if (catalogoAtual) {
      catalogoAtual = catalogos.find(c => String(c.catalogo) === String(catalogoAtual.catalogo)) || null;
    }
    if (!catalogoAtual && catalogos.length > 0) {
      const salvo = localStorage.getItem("mrdesk_catalogo");
      catalogoAtual = catalogos.find(c => String(c.catalogo) === salvo) || catalogos[0];
    }
    renderizarComboCatalogos();
    if (catalogoAtual) carregarDispositivos();
  } catch (err) {
    alert("Erro ao carregar catálogos: " + err.message);
  }
}

function renderizarComboCatalogos() {
  document.getElementById("combo-catalogo-nome").textContent = catalogoAtual ? catalogoAtual.nome : "Selecione um catálogo";

  const lista = document.getElementById("combo-catalogo-lista");
  lista.innerHTML = "";
  catalogos.forEach(cat => {
    const item = document.createElement("div");
    item.className = "combo-catalogo-item";
    item.innerHTML = `${ICONE_CATALOGO}<span>${escapeHtml(cat.nome)}</span>`;
    item.addEventListener("click", () => {
      catalogoAtual = cat;
      localStorage.setItem("mrdesk_catalogo", cat.catalogo);
      // o grupo (Ctrl+clique) era do catálogo anterior
      if (idsDoGrupo(document.getElementById("busca").value)) {
        document.getElementById("busca").value = "";
        guardarGrupoDaBusca();
        atualizarVisibilidadeBotaoLimpar();
      }
      document.getElementById("combo-catalogo-lista").classList.remove("aberto");
      renderizarComboCatalogos();
      carregarDispositivos();
    });
    lista.appendChild(item);
  });

  const sep2 = document.createElement("div");
  sep2.className = "combo-catalogo-separador";
  lista.appendChild(sep2);

  const novo = document.createElement("div");
  novo.className = "combo-catalogo-item combo-catalogo-especial";
  novo.innerHTML = `<svg class="icon" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg><span>Novo catálogo</span>`;
  novo.addEventListener("click", async () => {
    document.getElementById("combo-catalogo-lista").classList.remove("aberto");
    const nome = prompt("Nome do novo catálogo:");
    if (!nome) return;
    try {
      const resp = await fetch(`${API}/catalogos`, {
        method: "POST", headers: headersAuth(), body: JSON.stringify({ nome })
      });
      const data = await resp.json();
      if (data.success) {
        await carregarCatalogos();
      } else {
        alert("Erro ao criar catálogo: " + data.error);
      }
    } catch (err) {
      alert("Erro ao criar catálogo: " + err.message);
    }
  });
  lista.appendChild(novo);

  // Editar o catalogo selecionado (nome e senha geral do tecnico) - so o admin
  // (o catálogo "Novos" é fixo: recebe as máquinas no primeiro acesso e não muda de nome)
  if (usuarioAdmin && catalogoAtual && !catalogoAtual.fixo) {
    const editar = document.createElement("div");
    editar.className = "combo-catalogo-item combo-catalogo-especial";
    editar.innerHTML = `${ICONE_EDITAR}<span>Editar catálogo</span>`;
    editar.addEventListener("click", () => {
      document.getElementById("combo-catalogo-lista").classList.remove("aberto");
      abrirModalCatalogo(catalogoAtual);
    });
    lista.appendChild(editar);
  }
}

// ---- Editar catálogo (só admin) ----
function abrirModalCatalogo(cat) {
  document.getElementById("erro-modal-catalogo").style.display = "none";
  document.getElementById("catalogo-id").value = cat.catalogo;
  document.getElementById("catalogo-nome").value = cat.nome || "";
  document.getElementById("overlay-form-catalogo").style.display = "flex";
}

function fecharModalCatalogo() {
  document.getElementById("overlay-form-catalogo").style.display = "none";
}
document.getElementById("btn-cancelar-form-catalogo").addEventListener("click", fecharModalCatalogo);

document.getElementById("form-catalogo").addEventListener("submit", async (e) => {
  e.preventDefault();
  const id = document.getElementById("catalogo-id").value;
  const nome = document.getElementById("catalogo-nome").value.trim();
  const erroEl = document.getElementById("erro-modal-catalogo");
  erroEl.style.display = "none";
  try {
    const resp = await fetch(`${API}/catalogos/${id}`, {
      method: "PUT", headers: headersAuth(), body: JSON.stringify({ nome })
    });
    const data = await resp.json();
    if (data.success) {
      fecharModalCatalogo();
      await carregarCatalogos();
    } else {
      erroEl.textContent = data.error || "Erro ao salvar.";
      erroEl.style.display = "block";
    }
  } catch (err) {
    erroEl.textContent = "Erro de conexão: " + err.message;
    erroEl.style.display = "block";
  }
});

document.getElementById("combo-catalogo-btn").addEventListener("click", (e) => {
  e.stopPropagation();
  document.getElementById("combo-catalogo-lista").classList.toggle("aberto");
});
document.addEventListener("click", () => {
  document.getElementById("combo-catalogo-lista").classList.remove("aberto");
  document.getElementById("menu-usuario-lista").classList.remove("aberto");
  fecharMenuFlutuante();
});

// Regra geral das janelas (04/10/2026): ESC fecha a janela que está na frente,
// do mesmo jeito que o botão Cancelar/Fechar dela. Vale pra qualquer janela
// nova: basta o bloco ter id começando por "overlay" e um botão com id
// começando por "btn-cancelar" ou "btn-fechar".
// Formulário em que algo foi digitado não fecha com ESC, pra não perder o que
// foi editado: aí só o botão Cancelar (ou Salvar) fecha. A janela dá uma
// balançada pra mostrar que o ESC foi visto.
function fecharJanelaDaFrente() {
  const abertas = [...document.querySelectorAll('[id^="overlay"]')]
    .filter(o => getComputedStyle(o).display !== "none");
  if (!abertas.length) return false;
  // a da frente é a de maior z-index; empatando, a que vem depois na página
  const z = o => Number(getComputedStyle(o).zIndex) || 0;
  const frente = abertas.reduce((a, b) => (z(b) >= z(a) ? b : a));
  if (frente.dataset.editado === "1") {
    const caixa = frente.firstElementChild;
    if (caixa) {
      caixa.classList.remove("janela-editada");
      void caixa.offsetWidth;   // reinicia a animação
      caixa.classList.add("janela-editada");
    }
    return true;
  }
  const botao = frente.querySelector('button[id^="btn-cancelar"], button[id^="btn-fechar"]');
  if (botao) botao.click(); else frente.style.display = "none";
  return true;
}

// Marca a janela como editada quando o usuário mexe num campo de formulário
// dela (preencher os campos por código ao abrir não conta), e desmarca quando
// a janela fecha.
["input", "change"].forEach(tipo => document.addEventListener(tipo, (e) => {
  if (!e.isTrusted || !e.target.closest || !e.target.closest("form")) return;
  const janela = e.target.closest('[id^="overlay"]');
  if (janela) janela.dataset.editado = "1";
}, true));
document.querySelectorAll('[id^="overlay"]').forEach(janela => {
  new MutationObserver(() => {
    if (getComputedStyle(janela).display === "none") delete janela.dataset.editado;
  }).observe(janela, { attributes: true, attributeFilter: ["style", "class"] });
});

// ESC fecha a janela da frente; sem janela aberta, fecha o menu do usuário, o
// menu de catálogo e o menu flutuante de ações da linha.
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    if (fecharJanelaDaFrente()) { e.preventDefault(); return; }
    document.getElementById("combo-catalogo-lista").classList.remove("aberto");
    document.getElementById("menu-usuario-lista").classList.remove("aberto");
    fecharMenuFlutuante();
  }
});

// silencioso (atualização automática e depois de conectar): mantém a lista
// na mesma posição de rolagem e não mostra alerta se a rede falhar.
// No catálogo "Novos" os filtros não valem (o servidor mostra tudo o que
// chegou): as caixas ficam apagadas pra deixar isso claro.
function atualizarFiltrosDoCatalogo() {
  const semFiltro = !!(catalogoAtual && catalogoAtual.fixo);
  ["check-ativos", "check-instalado", "check-servidor"].forEach(id => {
    const caixa = document.getElementById(id);
    caixa.disabled = semFiltro;
    caixa.closest("label").classList.toggle("filtro-sem-efeito", semFiltro);
  });
}

async function carregarDispositivos(silencioso = false) {
  atualizarFiltrosDoCatalogo();
  carregarContadorDeAcessos();
  const caixa = document.querySelector("#area-dispositivos > .tabela-wrapper");
  const rolagem = caixa ? caixa.scrollTop : 0;
  try {
    const filtroAtivo = document.getElementById("check-ativos").checked ? "S" : "N";
    const filtroServidor = document.getElementById("check-servidor").checked ? "S" : "N";
    const filtroInstalado = document.getElementById("check-instalado").checked ? "S" : "N";
    const resp = await fetch(
      `${API}/devices?catalogo=${catalogoAtual.catalogo}&ativo=${filtroAtivo}&servidor=${filtroServidor}&instalado=${filtroInstalado}`,
      { headers: headersAuth() }
    );
    if (resp.status === 401) { mostrarLogin(); return; }
    const data = await resp.json();
    dispositivos = data.devices || [];
    versaoPublicada = data.versao_publicada || null;
    atualizarDicaDeDesatualizados();
    restaurarGrupoDaBusca();
    renderizarTabela();
    if (silencioso && caixa) caixa.scrollTop = rolagem;
    else restaurarRolagemDoF5();
  } catch (err) {
    if (!silencioso) alert("Erro ao carregar dispositivos: " + err.message);
  }
}

// F5: a lista volta na mesma posição. Ao sair da página guarda a rolagem e o
// catálogo (só nesta aba); na primeira carga depois do F5, se o catálogo é o
// mesmo, restaura. Vale uma vez só (trocar de catálogo/filtro começa do topo).
const CHAVE_ROLAGEM_F5 = "mrdesk_rolagem_lista";
let rolagemDoF5Pendente = true;
window.addEventListener("pagehide", () => {
  const caixa = document.querySelector("#area-dispositivos > .tabela-wrapper");
  if (!caixa || !catalogoAtual) return;
  try {
    sessionStorage.setItem(CHAVE_ROLAGEM_F5, JSON.stringify({ catalogo: String(catalogoAtual.catalogo), topo: caixa.scrollTop }));
  } catch (_) {}
});
function restaurarRolagemDoF5() {
  if (!rolagemDoF5Pendente) return;
  rolagemDoF5Pendente = false;
  try {
    const salvo = JSON.parse(sessionStorage.getItem(CHAVE_ROLAGEM_F5) || "null");
    sessionStorage.removeItem(CHAVE_ROLAGEM_F5);
    const caixa = document.querySelector("#area-dispositivos > .tabela-wrapper");
    if (salvo && caixa && catalogoAtual && salvo.catalogo === String(catalogoAtual.catalogo)) caixa.scrollTop = salvo.topo;
  } catch (_) {}
}

// Item 14: atualiza a lista (on-line/off-line, inativo) a cada 5 min, sem
// mexer na posição. Pula se a aba está escondida, sem login ou com o menu de
// ações aberto.
const ATUALIZAR_LISTA_MS = 5 * 60 * 1000;
setInterval(() => {
  if (document.hidden) return;
  if (document.getElementById("app").style.display === "none") return;
  if (usuarioSuper) { carregarSemConta(); return; }
  if (!catalogoAtual) return;
  if (document.getElementById("menu-flutuante").style.display === "block") return;
  carregarDispositivos(true);
}, ATUALIZAR_LISTA_MS);

document.getElementById("check-ativos").addEventListener("change", (e) => {
  localStorage.setItem("mrdesk_filtro_ativos", e.target.checked ? "1" : "0");
  carregarDispositivos();
});
document.getElementById("check-servidor").addEventListener("change", (e) => {
  localStorage.setItem("mrdesk_filtro_servidor", e.target.checked ? "1" : "0");
  carregarDispositivos();
});
document.getElementById("check-instalado").addEventListener("change", (e) => {
  localStorage.setItem("mrdesk_filtro_instalado", e.target.checked ? "1" : "0");
  carregarDispositivos();
});

// Sem cliente informado, o dispositivo é identificado só pelo apelido.
function rotuloDispositivo(d) {
  return d.cliente ? `"${d.cliente}" (${d.apelido})` : `"${d.apelido}"`;
}

// Tira os acentos (e o cedilha) pra comparar textos na busca.
function semAcento(texto) {
  return String(texto || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "");
}

function renderizarTabela() {
  const termoBruto = document.getElementById("busca").value.toLowerCase();
  // Se o texto digitado for so numeros e espacos (ex: "207 575 694"
  // colado com a formatacao), remove os espacos antes de comparar
  // com o ID puro. Buscas por texto (cliente/apelido) so recebem trim.
  // Grupo de IDs separados por vírgula (seleção com Ctrl+clique): mostra só eles.
  const grupo = idsDoGrupo(termoBruto);
  const apenasNumerosEEspacos = !grupo && /^[0-9\s]+$/.test(termoBruto.trim()) && termoBruto.trim() !== "";
  const termo = apenasNumerosEEspacos ? termoBruto.replace(/\s+/g, "") : termoBruto.trim();

  // Cliente e apelido: a busca ignora acentos ("joao" acha "João")
  const termoSemAcento = semAcento(termo);
  const filtrados = grupo
    ? dispositivos.filter(d => grupo.includes(d.id))
    : dispositivos.filter(d =>
        semAcento((d.cliente || "").toLowerCase()).includes(termoSemAcento) ||
        semAcento((d.apelido || "").toLowerCase()).includes(termoSemAcento) ||
        d.id.includes(termo) ||
        // coluna Versão MR1 (só a conta da Sysrs tem): compara com o texto como foi digitado
        (d.versao_erp || "").toLowerCase().includes(termoBruto.trim())
      );

  const corpo = document.getElementById("corpo-tabela");
  corpo.innerHTML = "";

  filtrados.forEach(d => {
    const tr = document.createElement("tr");
    tr.className = "linha-dispositivo" + (d.id === lerUltimoAcessado() ? " ultimo-acessado" : "")
      + (marcadosComCtrl.has(d.id) ? " linha-marcada" : "");
    tr.dataset.id = d.id;
    const opacidadeConteudo = d.ativo === "N" ? "opacity:0.5;" : "";

    let statusClasse = "";
    if (d.online === true) statusClasse = "online";
    else if (d.online === false) statusClasse = "offline";

    // Off-line: ha quanto tempo esta off-line. On-line: so mostra algo se estiver
    // sem uso de teclado/mouse ha 3 min ou mais (item 16).
    const tempoDecorrido = d.online ? textoSemUso(d.segundos_sem_uso) : calcularTempoDecorrido(d.ultima_vez_online, d.online);

    tr.innerHTML = `
      <td class="col-status-conectar" style="${opacidadeConteudo}">
        <div class="status-conectar-wrap">
          <span class="bolinha-status ${statusClasse}" title="${statusClasse === 'online' ? 'On-line' : statusClasse === 'offline' ? 'Off-line' : 'Status desconhecido'}"></span>
          <button class="btn-conectar-icone" title="Conectar" data-acao="conectar" data-id="${d.id}">${ICONE_CONECTAR}</button>
        </div>
      </td>
      <td style="${opacidadeConteudo}">${escapeHtml(d.cliente || d.apelido)}</td>
      <td style="${opacidadeConteudo}">${d.cliente ? escapeHtml(d.apelido) : ""}</td>
      <td class="id-mono" style="${opacidadeConteudo}">${formatarId(d.id)}</td>
      <td class="data-centralizada" style="${opacidadeConteudo}">
        ${formatarDataHora(d.ultima_vez_online)}
        ${tempoDecorrido ? `<div style="font-size:11px;font-style:italic;color:${d.online ? "var(--verde)" : "var(--vermelho)"};">${tempoDecorrido}</div>` : ""}
      </td>
      <td class="col-desatualizado" style="${opacidadeConteudo}">${iconeDesatualizado(d)}</td>
      <td class="col-sistema" style="${opacidadeConteudo}" title="${escapeHtml(hintSistema(d))}">${escapeHtml(sistemaCurto(d.sistema))}</td>
      <td class="col-versao${versaoAbaixoDaMinima(d.versao_erp) ? " versao-antiga" : ""}" style="${opacidadeConteudo}"><span${versaoAbaixoDaMinima(d.versao_erp) ? ` title="Abaixo da versão mínima (${escapeHtml(lerVersaoMinima())})"` : ""}>${escapeHtml(d.versao_erp || "")}</span></td>
      <td class="acoes-linha col-acoes-estreita">
        <button title="Transferir arquivos" data-acao="arquivos" data-id="${d.id}">${ICONE_ARQUIVOS}</button>
        <button title="Mais ações" data-acao="menu" data-id="${d.id}">${ICONE_PONTOS}</button>
      </td>`;
    corpo.appendChild(tr);
  });

  document.getElementById("sem-resultados").style.display = filtrados.length ? "none" : "block";
  document.getElementById("contador").textContent = `${filtrados.length} de ${dispositivos.length} dispositivos`;

  atualizarBotaoAcessar(apenasNumerosEEspacos ? termo : "", filtrados);
}

// ---- Botão "Acessar" da busca ----
// Quando o texto da busca é um ID completo (7 a 10 dígitos) e esse ID não
// aparece na lista (catálogo ou filtros escondendo, ou ID não cadastrado),
// mostra o botão "Acessar" ao lado da busca. O hint explica o que esconde o
// dispositivo, comparando com o catálogo e os filtros marcados agora.
let idBotaoAcessar = null;
let timerLocalizar = null;
// Resultado da última consulta: { id, erro, encontrado, device }
let localizado = null;

function atualizarBotaoAcessar(idDigitado, filtrados) {
  const btn = document.getElementById("btn-acessar-id");
  const idCompleto = /^\d{7,10}$/.test(idDigitado);
  const visivelNaLista = idCompleto && filtrados.some(d => d.id === idDigitado);

  if (!idCompleto || visivelNaLista) {
    clearTimeout(timerLocalizar);
    btn.style.display = "none";
    idBotaoAcessar = null;
    return;
  }

  btn.style.display = "flex";
  if (idBotaoAcessar !== idDigitado) {
    idBotaoAcessar = idDigitado;
    clearTimeout(timerLocalizar);
    btn.title = "Verificando...";
    // Pequena espera pra não consultar o servidor a cada tecla.
    timerLocalizar = setTimeout(() => localizarId(idDigitado), 300);
  } else {
    // Mesmo ID, mas os filtros podem ter mudado: refaz o texto do hint.
    montarHintAcessar();
  }
}

function motivosOcultacao(dev) {
  const motivos = [];
  const filtroAtivo = document.getElementById("check-ativos").checked ? "S" : "N";
  const filtroInstalado = document.getElementById("check-instalado").checked ? "S" : "N";
  const filtroServidor = document.getElementById("check-servidor").checked ? "S" : "N";

  if (!catalogoAtual || String(dev.catalogo) !== String(catalogoAtual.catalogo)) {
    motivos.push(`está no catálogo "${dev.catalogo_nome || dev.catalogo}"`);
  }
  // No catálogo "Novos" os filtros não escondem nada
  const novos = catalogos.find(c => c.fixo);
  if (novos && String(dev.catalogo) === String(novos.catalogo)) return motivos;
  if ((dev.ativo || "S") !== filtroAtivo) {
    motivos.push(dev.ativo === "N" ? "está inativo" : "está ativo");
  }
  if ((dev.instalado || "S") !== filtroInstalado) {
    motivos.push(dev.instalado === "N" ? "não está instalado" : "está instalado");
  }
  if ((dev.servidor || "N") !== filtroServidor) {
    motivos.push(dev.servidor === "S" ? "é servidor" : "não é servidor");
  }
  return motivos;
}

function montarHintAcessar() {
  const btn = document.getElementById("btn-acessar-id");
  if (!localizado || localizado.id !== idBotaoAcessar) return;
  let hint;
  if (localizado.erro) {
    hint = "Não foi possível verificar este ID.";
  } else if (!localizado.encontrado) {
    hint = "ID não cadastrado.";
  } else {
    const d = localizado.device;
    const motivos = motivosOcultacao(d);
    hint = d.cliente ? `${d.cliente} — ${d.apelido}` : d.apelido;
    if (motivos.length) hint += `\nOculto porque ${motivos.join(", ")}.`;
  }
  btn.title = `${hint}\nEnter ou clique para acessar.`;
}

async function localizarId(id) {
  let resultado;
  try {
    const resp = await fetch(`${API}/devices/localizar?id=${id}`, { headers: headersAuth() });
    if (resp.status === 401) { mostrarLogin(); return; }
    const data = await resp.json();
    resultado = data.success
      ? { id, encontrado: data.encontrado, device: data.device }
      : { id, erro: true };
  } catch (err) {
    resultado = { id, erro: true };
  }
  localizado = resultado;
  montarHintAcessar();
}

function acessarIdDigitado() {
  if (idBotaoAcessar) conectar(idBotaoAcessar, "connect");
}

document.getElementById("btn-acessar-id").addEventListener("click", acessarIdDigitado);
document.getElementById("busca").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && idBotaoAcessar) {
    e.preventDefault();
    acessarIdDigitado();
  }
});

function escapeHtml(txt) {
  const div = document.createElement("div");
  div.textContent = txt || "";
  return div.innerHTML;
}

// ---- Grupo de dispositivos (pedido do Celso, 03/10) ----
// Com o Ctrl pressionado, cada clique numa linha marca/desmarca o dispositivo.
// Ao soltar o Ctrl, os IDs vão pra busca separados por vírgula e a lista mostra
// só eles (útil pra acompanhar um grupo, ex.: clientes a atualizar). Com o
// grupo já na busca, Ctrl+clique tira ou põe um dispositivo nele. Apagar a
// busca volta ao normal. O grupo fica guardado até fechar a aba (sobrevive ao
// F5 e à recarga automática) e vale pro catálogo em que foi montado.
const CHAVE_GRUPO = "mrdesk_grupo_busca";
const marcadosComCtrl = new Set();

// Devolve os IDs se o texto for um grupo ("111 222 333, 444555666"); senão null.
function idsDoGrupo(texto) {
  if (!/[,;]/.test(texto) || !/^[0-9\s,;]+$/.test(texto)) return null;
  return texto.split(/[,;]/).map(t => t.replace(/\D/g, "")).filter(t => t);
}

// Guarda o texto da busca até fechar a aba, pra sobreviver ao F5: tanto o
// grupo (Ctrl+clique) quanto uma busca comum (04/10/2026).
function guardarGrupoDaBusca() {
  const texto = document.getElementById("busca").value;
  try {
    if (texto.trim() && catalogoAtual) {
      sessionStorage.setItem(CHAVE_GRUPO, JSON.stringify({
        catalogo: String(catalogoAtual.catalogo), texto, grupo: !!idsDoGrupo(texto)
      }));
    } else {
      sessionStorage.removeItem(CHAVE_GRUPO);
    }
  } catch (e) { /* sem armazenamento: a busca só não sobrevive ao F5 */ }
}

// Depois do F5: devolve o texto à busca. O grupo só volta se o catálogo aberto
// é o mesmo em que foi montado; a busca comum volta em qualquer catálogo.
function restaurarGrupoDaBusca() {
  try {
    const salvo = JSON.parse(sessionStorage.getItem(CHAVE_GRUPO) || "null");
    if (!salvo || !catalogoAtual || document.getElementById("busca").value) return;
    const ehGrupo = salvo.grupo !== undefined ? salvo.grupo : !!idsDoGrupo(salvo.texto);
    if (ehGrupo && salvo.catalogo !== String(catalogoAtual.catalogo)) return;
    document.getElementById("busca").value = salvo.texto;
    atualizarVisibilidadeBotaoLimpar();
  } catch (e) { /* ignora */ }
}

function aplicarMarcadosComCtrl() {
  if (!marcadosComCtrl.size) return;
  const campo = document.getElementById("busca");
  const grupo = new Set(idsDoGrupo(campo.value) || []);
  // quem já estava no grupo sai; quem não estava entra
  marcadosComCtrl.forEach(id => { if (grupo.has(id)) grupo.delete(id); else grupo.add(id); });
  marcadosComCtrl.clear();
  // a vírgula no fim mantém o texto como grupo mesmo com um ID só
  campo.value = grupo.size ? [...grupo].map(formatarId).join(", ") + (grupo.size === 1 ? "," : "") : "";
  guardarGrupoDaBusca();
  renderizarTabela();
  atualizarVisibilidadeBotaoLimpar();
}

document.getElementById("corpo-tabela").addEventListener("click", (e) => {
  if (!(e.ctrlKey || e.metaKey) || e.target.closest("button")) return;
  const tr = e.target.closest("tr.linha-dispositivo");
  if (!tr) return;
  e.preventDefault();
  const id = tr.dataset.id;
  if (marcadosComCtrl.has(id)) marcadosComCtrl.delete(id); else marcadosComCtrl.add(id);
  tr.classList.toggle("linha-marcada", marcadosComCtrl.has(id));
});
// evita selecionar texto ao clicar com o Ctrl
document.getElementById("corpo-tabela").addEventListener("mousedown", (e) => {
  if (e.ctrlKey || e.metaKey) e.preventDefault();
});
window.addEventListener("keyup", (e) => {
  if (e.key === "Control" || e.key === "Meta") aplicarMarcadosComCtrl();
});
// soltou o Ctrl fora da janela (ex.: trocou de programa): aplica também
window.addEventListener("blur", aplicarMarcadosComCtrl);

function atualizarVisibilidadeBotaoLimpar() {
  const temTexto = document.getElementById("busca").value.length > 0;
  document.getElementById("btn-limpar-busca").style.display = temTexto ? "block" : "none";
}

document.getElementById("busca").addEventListener("input", () => {
  guardarGrupoDaBusca();
  renderizarTabela();
  atualizarVisibilidadeBotaoLimpar();
});

document.getElementById("btn-limpar-busca").addEventListener("click", () => {
  const campo = document.getElementById("busca");
  campo.value = "";
  campo.focus();
  guardarGrupoDaBusca();
  renderizarTabela();
  atualizarVisibilidadeBotaoLimpar();
});

// Último dispositivo acessado (01/10): linha com fundo azul claro. Fica
// guardado neste navegador (cada computador lembra o último acessado dali).
const CHAVE_ULTIMO_ACESSADO = "mrdesk_ultimo_acessado";
function lerUltimoAcessado() {
  try { return localStorage.getItem(CHAVE_ULTIMO_ACESSADO); } catch (_) { return null; }
}
function marcarUltimoAcessado(id) {
  try { localStorage.setItem(CHAVE_ULTIMO_ACESSADO, id); } catch (_) {}
  document.querySelectorAll("tr.linha-dispositivo.ultimo-acessado").forEach(tr => tr.classList.remove("ultimo-acessado"));
  const linha = document.querySelector(`tr.linha-dispositivo[data-id="${CSS.escape(String(id))}"]`);
  if (linha) linha.classList.add("ultimo-acessado");
}

async function conectar(id, modo) {
  try {
    const resp = await fetch(`${API}/devices/${id}/connect?mode=${modo}`, { headers: headersAuth() });
    const data = await resp.json();
    if (data.success) {
      marcarUltimoAcessado(id);
      window.location.href = data.link;
      // Atualiza a lista (bolinhas on-line/off-line) a cada conexao, sem
      // ficar recarregando sozinha o tempo todo (pedido do Celso, 30/09)
      setTimeout(() => carregarDispositivos(true), 1500);
    } else {
      alert("Erro ao gerar link: " + data.error);
    }
  } catch (err) {
    alert("Erro ao conectar: " + err.message);
  }
}

document.getElementById("corpo-tabela").addEventListener("dblclick", (e) => {
  const linha = e.target.closest("tr.linha-dispositivo");
  if (linha && !e.target.closest("button")) conectar(linha.dataset.id, "connect");
});

let idMenuAtual = null;

document.getElementById("corpo-tabela").addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;

  e.stopPropagation();
  const id = btn.dataset.id;
  const acao = btn.dataset.acao;

  if (acao === "conectar") { conectar(id, "connect"); return; }
  if (acao === "arquivos") { conectar(id, "file-transfer"); return; }

  if (acao === "menu") {
    const menu = document.getElementById("menu-flutuante");
    const jaAbertoParaEsseId = menu.style.display === "block" && idMenuAtual === id;
    fecharMenuFlutuante();
    if (!jaAbertoParaEsseId) {
      idMenuAtual = id;
      const rect = btn.getBoundingClientRect();
      menu.style.display = "block";
      // Posiciona abaixo do botao; se nao couber embaixo, abre para cima
      const alturaEstimada = usuarioAdmin ? 210 : 130;
      if (rect.bottom + alturaEstimada > window.innerHeight) {
        menu.style.top = (rect.top - alturaEstimada) + "px";
      } else {
        menu.style.top = (rect.bottom + 4) + "px";
      }
      const larguraMenu = 180;
      let left = rect.right - larguraMenu;
      if (left < 8) left = 8;
      menu.style.left = left + "px";
    }
    return;
  }
});

// A lista rola dentro da propria caixa: fecha o menu de acoes ao rolar,
// senao ele ficaria parado longe da linha
document.querySelector("#area-dispositivos > .tabela-wrapper").addEventListener("scroll", () => fecharMenuFlutuante());

function fecharMenuFlutuante() {
  document.getElementById("menu-flutuante").style.display = "none";
  idMenuAtual = null;
}

document.getElementById("menu-flutuante").addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;
  e.stopPropagation();
  const acao = btn.dataset.acao;
  const id = idMenuAtual;
  fecharMenuFlutuante();

  if (acao === "editar") {
    const dev = dispositivos.find(d => d.id === id);
    abrirModal(dev);
  }

  if (acao === "excluir") {
    const dev = dispositivos.find(d => d.id === id);
    if (confirm(`Remover o dispositivo ${rotuloDispositivo(dev)} da sua conta?\n\n` +
                `O histórico de acessos continua guardado. Se um técnico acessar essa máquina de novo, ela volta para a conta.`)) {
      const resp = await fetch(`${API}/devices/${id}`, { method: "DELETE", headers: headersAuth() });
      const data = await resp.json();
      if (data.success) {
        carregarDispositivos();
      } else {
        alert("Erro ao remover: " + data.error);
      }
    }
  }

  if (acao === "mover") {
    abrirModalMover(id);
  }

  if (acao === "auditoria") {
    abrirModalAuditoria(id);
  }

  if (acao === "licenca") {
    abrirModalLicenca(id);
  }

  // Item 9: Windows reinstalado (mesmo ID, máquina nova) - apaga a máquina
  // registrada; o próximo contato do MRDesk grava a nova.
  if (acao === "liberar-maquina") {
    const dev = dispositivos.find(d => d.id === id);
    if (confirm(`Liberar nova máquina para ${rotuloDispositivo(dev)}?\n\n` +
        "Use quando o Windows desse computador foi reinstalado: até liberar, ele fica off-line no painel e não gera auditoria. " +
        "O próximo contato do MRDesk registra a máquina nova.")) {
      try {
        const resp = await fetch(`${API}/devices/${id}/liberar-maquina`, { method: "POST", headers: headersAuth() });
        const data = await resp.json();
        if (data.success) {
          alert("Máquina liberada. Em alguns segundos o computador volta a aparecer on-line.");
          setTimeout(() => carregarDispositivos(true), 20000);
        } else {
          alert("Erro ao liberar: " + data.error);
        }
      } catch (err) {
        alert("Erro ao liberar: " + err.message);
      }
    }
  }
});

function abrirModalMover(id) {
  idParaMover = id;
  const lista = document.getElementById("lista-catalogos-mover");
  lista.innerHTML = "";
  catalogos.filter(c => c.catalogo !== catalogoAtual.catalogo).forEach(cat => {
    const item = document.createElement("div");
    item.className = "catalogo-mover-item";
    item.textContent = cat.nome;
    item.addEventListener("click", async () => {
      try {
        const resp = await fetch(`${API}/devices/${idParaMover}/catalogo`, {
          method: "PUT", headers: headersAuth(), body: JSON.stringify({ catalogo: cat.catalogo })
        });
        const data = await resp.json();
        if (data.success) {
          fecharModalMover();
          carregarDispositivos();
        } else {
          alert("Erro ao mover: " + data.error);
        }
      } catch (err) {
        alert("Erro ao mover: " + err.message);
      }
    });
    lista.appendChild(item);
  });
  document.getElementById("overlay-catalogo").style.display = "flex";
}

function fecharModalMover() {
  document.getElementById("overlay-catalogo").style.display = "none";
}
document.getElementById("btn-cancelar-mover").addEventListener("click", fecharModalMover);

// ---- Licença MR1 do dispositivo (item 30, só admin) ----
// Informa o CNPJ, escolhe a licença (só as não antigas) e liga ao dispositivo.
let idParaLicenca = null;

function textoLicenca(l) {
  return `${escapeHtml(l.nome || "(sem nome)")}<div class="licenca-item-linha2">Serial ${escapeHtml(l.serial)}`
    + ` · versão ${escapeHtml(l.versao || "-")}${l.ativa === "S" ? "" : " · inativa"}`
    + `${l.id_mrdesk ? " · ligada ao ID " + formatarId(l.id_mrdesk) : ""}</div>`;
}

function erroLicenca(msg) {
  const el = document.getElementById("erro-licenca");
  el.textContent = msg || "";
  el.style.display = msg ? "block" : "none";
}

async function carregarLicencaAtual() {
  const atual = document.getElementById("licenca-atual");
  const btnDesligar = document.getElementById("btn-desligar-licenca");
  atual.textContent = "Carregando...";
  btnDesligar.style.display = "none";
  try {
    const resp = await fetch(`${API}/devices/${idParaLicenca}/licenca`, { headers: headersAuth() });
    const data = await resp.json();
    if (data.success && data.licenca) {
      atual.innerHTML = "Licença ligada hoje: " + textoLicenca(data.licenca);
      btnDesligar.style.display = "inline-block";
    } else {
      atual.textContent = "Nenhuma licença ligada a este dispositivo.";
    }
  } catch (err) {
    atual.textContent = "";
    erroLicenca("Erro ao consultar: " + err.message);
  }
}

function abrirModalLicenca(id) {
  idParaLicenca = id;
  const dev = dispositivos.find(d => d.id === id);
  document.getElementById("licenca-device").textContent = `${dev.cliente ? `${dev.cliente} (${dev.apelido})` : dev.apelido} — ID ${formatarId(id)}`;
  document.getElementById("licenca-cnpj").value = "";
  document.getElementById("lista-licencas").style.display = "none";
  document.getElementById("lista-licencas").innerHTML = "";
  erroLicenca("");
  document.getElementById("overlay-licenca").style.display = "flex";
  document.getElementById("licenca-cnpj").focus();
  carregarLicencaAtual();
}

function fecharModalLicenca() {
  document.getElementById("overlay-licenca").style.display = "none";
}
document.getElementById("btn-fechar-licenca").addEventListener("click", fecharModalLicenca);

document.getElementById("form-licenca").addEventListener("submit", async (e) => {
  e.preventDefault();
  erroLicenca("");
  const lista = document.getElementById("lista-licencas");
  const cnpj = document.getElementById("licenca-cnpj").value.trim();
  if (!cnpj) { erroLicenca("Informe o CNPJ."); return; }
  try {
    const resp = await fetch(`${API}/licencas?cnpj=${encodeURIComponent(cnpj)}`, { headers: headersAuth() });
    const data = await resp.json();
    if (!data.success) { erroLicenca(data.error || "Erro na busca."); return; }
    lista.innerHTML = "";
    lista.style.display = "block";
    if (!data.licencas.length) {
      lista.innerHTML = '<div class="catalogo-mover-item" style="cursor:default;">Nenhuma licença (não antiga) com esse CNPJ.</div>';
      return;
    }
    data.licencas.forEach((l) => {
      const item = document.createElement("div");
      item.className = "catalogo-mover-item licenca-item" + (l.id_mrdesk === idParaLicenca ? " atual" : "");
      item.innerHTML = textoLicenca(l);
      item.addEventListener("click", async () => {
        if (l.id_mrdesk && l.id_mrdesk !== idParaLicenca &&
            !confirm(`Essa licença está ligada ao ID ${formatarId(l.id_mrdesk)}. Passar para este dispositivo?`)) return;
        try {
          const r = await fetch(`${API}/devices/${idParaLicenca}/licenca`, {
            method: "PUT", headers: headersAuth(), body: JSON.stringify({ cnpj: l.cnpj, serial: l.serial })
          });
          const d = await r.json();
          if (d.success) {
            fecharModalLicenca();
            carregarDispositivos(true);
          } else {
            erroLicenca("Erro ao ligar: " + d.error);
          }
        } catch (err) {
          erroLicenca("Erro ao ligar: " + err.message);
        }
      });
      lista.appendChild(item);
    });
  } catch (err) {
    erroLicenca("Erro na busca: " + err.message);
  }
});

document.getElementById("btn-desligar-licenca").addEventListener("click", async () => {
  if (!confirm("Desligar a licença deste dispositivo? A coluna Versão MR1 fica vazia para ele.")) return;
  try {
    const r = await fetch(`${API}/devices/${idParaLicenca}/licenca`, { method: "DELETE", headers: headersAuth() });
    const d = await r.json();
    if (d.success) {
      fecharModalLicenca();
      carregarDispositivos(true);
    } else {
      erroLicenca("Erro ao desligar: " + d.error);
    }
  } catch (err) {
    erroLicenca("Erro ao desligar: " + err.message);
  }
});

let idParaAuditoria = null;

// Coluna "permissao" da auditoria (controle de acesso - item 6A)
const TEXTO_PERMISSAO = { P: "Permitida", B: "Bloqueada", F: "Falha na verificação" };
// Coluna "autenticacao" (item 33): como o acesso foi autorizado no MRDesk
const TEXTO_AUTENTICACAO = { 1: "Aceite na tela", 2: "Senha temporária", 3: "Senha permanente", 4: "Troca de lado" };

function formatarDataHora(isoString) {
  if (!isoString) return "-";
  const d = new Date(isoString);
  const pad = (n) => String(n).padStart(2, "0");
  return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()} `
    + `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function formatarDuracao(segundos) {
  if (segundos === null || segundos === undefined) return "Em andamento";
  const h = Math.floor(segundos / 3600);
  const m = Math.floor((segundos % 3600) / 60);
  const s = segundos % 60;
  const partes = [];
  if (h > 0) partes.push(`${h}h`);
  if (m > 0 || h > 0) partes.push(`${m}m`);
  partes.push(`${s}s`);
  return partes.join(" ");
}

function dataParaInputISO(date) {
  const pad = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

async function carregarAuditoria() {
  const inicio = document.getElementById("auditoria-data-inicio").value;
  const fim = document.getElementById("auditoria-data-fim").value;
  const corpo = document.getElementById("corpo-tabela-auditoria");
  corpo.innerHTML = "<tr><td colspan=\"8\">Carregando...</td></tr>";

  try {
    const resp = await fetch(
      `${API}/devices/${idParaAuditoria}/auditoria?inicio=${inicio}&fim=${fim}`,
      { headers: headersAuth() }
    );
    if (resp.status === 401) { mostrarLogin(); return; }
    const data = await resp.json();

    if (!data.success) {
      corpo.innerHTML = `<tr><td colspan="8">Erro ao carregar: ${data.error || ""}</td></tr>`;
      return;
    }

    if (data.registros.length === 0) {
      corpo.innerHTML = "<tr><td colspan=\"8\">Nenhuma conexão encontrada no período.</td></tr>";
      return;
    }

    corpo.innerHTML = "";
    data.registros.forEach((r) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="centralizado">${formatarDataHora(r.inicio)}</td>
        <td>${formatarDuracao(r.duracao_segundos)}</td>
        <td>${escapeHtml(r.nome || "-")}</td>
        <td style="text-align:right;">${r.origem ? formatarId(r.origem) : "-"}</td>
        <td>${r.tipo || "-"}</td>
        <td>${TEXTO_AUTENTICACAO[r.autenticacao] || "-"}</td>
        <td class="permissao-${r.permissao || ""}">${TEXTO_PERMISSAO[r.permissao] || "-"}</td>
        <td class="col-ip">${r.ip || "-"}</td>
      `;
      corpo.appendChild(tr);
    });
  } catch (err) {
    corpo.innerHTML = `<tr><td colspan="8">Erro ao carregar: ${err.message}</td></tr>`;
  }
}

function abrirModalAuditoria(id) {
  idParaAuditoria = id;
  const hoje = new Date();
  const seteDiasAtras = new Date(hoje.getTime() - 7 * 24 * 60 * 60 * 1000);
  document.getElementById("auditoria-data-inicio").value = dataParaInputISO(seteDiasAtras);
  document.getElementById("auditoria-data-fim").value = dataParaInputISO(hoje);
  document.getElementById("overlay-auditoria").style.display = "flex";
  carregarAuditoria();
}

function fecharModalAuditoria() {
  document.getElementById("overlay-auditoria").style.display = "none";
}
document.getElementById("btn-cancelar-auditoria").addEventListener("click", fecharModalAuditoria);
document.getElementById("btn-filtrar-auditoria").addEventListener("click", carregarAuditoria);

// Só edição: o dispositivo entra na conta sozinho, no primeiro acesso de um técnico.
function abrirModal(dev) {
  if (!dev) return;
  document.getElementById("erro-modal").style.display = "none";
  document.getElementById("form-modal").reset();
  document.getElementById("modal-id-original").value = dev.id;
  document.getElementById("modal-id").value = formatarId(dev.id);
  document.getElementById("modal-id").disabled = true;
  document.getElementById("modal-apelido").value = dev.apelido || "";
  document.getElementById("modal-cliente").value = dev.cliente || "";
  document.getElementById("modal-ativo").checked = dev.ativo !== "N";
  document.getElementById("modal-servidor").checked = dev.servidor === "S";
  document.getElementById("overlay").style.display = "flex";
}

function fecharModal() {
  document.getElementById("overlay").style.display = "none";
}

document.getElementById("btn-cancelar-modal").addEventListener("click", fecharModal);

document.getElementById("modal-id").addEventListener("input", (e) => {
  if (e.target.disabled) return;
  const cursorNoFim = e.target.selectionStart === e.target.value.length;
  e.target.value = formatarId(e.target.value);
  if (cursorNoFim) e.target.setSelectionRange(e.target.value.length, e.target.value.length);
});

document.getElementById("form-modal").addEventListener("submit", async (e) => {
  e.preventDefault();
  const idOriginal = document.getElementById("modal-id-original").value;
  const id = document.getElementById("modal-id").value.replace(/\D/g, "");
  const apelido = document.getElementById("modal-apelido").value.trim();
  const cliente = document.getElementById("modal-cliente").value.trim();
  const ativo = document.getElementById("modal-ativo").checked ? "S" : "N";
  const servidor = document.getElementById("modal-servidor").checked ? "S" : "N";
  const erroEl = document.getElementById("erro-modal");
  erroEl.style.display = "none";

  try {
    const resp = await fetch(`${API}/devices/${idOriginal}`, {
      method: "PUT", headers: headersAuth(),
      body: JSON.stringify({ apelido, cliente, ativo, servidor })
    });
    const data = await resp.json();
    if (data.success) {
      fecharModal();
      carregarDispositivos();
    } else {
      erroEl.textContent = data.error || "Erro ao salvar.";
      erroEl.style.display = "block";
    }
  } catch (err) {
    erroEl.textContent = "Erro de conexão: " + err.message;
    erroEl.style.display = "block";
  }
});

// ---- Dispositivos sem conta (item 41 - só o superadmin) ----
async function carregarSemConta() {
  try {
    const resp = await fetch(`${API}/devices/sem-conta`, { headers: headersAuth() });
    if (resp.status === 401) { mostrarLogin(); return; }
    const data = await resp.json();
    const lista = data.devices || [];
    const corpo = document.getElementById("corpo-sem-conta");
    corpo.innerHTML = "";
    lista.forEach(d => {
      const statusClasse = d.online === true ? "online" : (d.online === false ? "offline" : "");
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="col-status-conectar"><span class="bolinha-status ${statusClasse}" title="${statusClasse === "online" ? "On-line" : statusClasse === "offline" ? "Off-line" : "Status desconhecido"}"></span></td>
        <td class="id-mono">${formatarId(d.id)}</td>
        <td>${escapeHtml(d.computador || "—")}</td>
        <td class="col-sistema" title="${escapeHtml(d.sistema || "")}">${escapeHtml(sistemaCurto(d.sistema))}</td>
        <td class="centralizado"><span class="${d.instalado === "N" ? "badge-nao" : "badge-sim"}">${d.instalado === "N" ? "Não" : "Sim"}</span></td>
        <td class="data-centralizada">${d.inclusao ? formatarDataHora(d.inclusao) : "—"}</td>
        <td class="data-centralizada">${d.ultima_vez_online ? formatarDataHora(d.ultima_vez_online) : "—"}</td>
        <td class="acoes-linha"><button title="Excluir" data-acao="excluir-sem-conta" data-id="${d.id}" data-nome="${escapeHtml(d.computador || "")}">${ICONE_REMOVER}</button></td>`;
      corpo.appendChild(tr);
    });
    document.getElementById("sem-conta-vazio").style.display = lista.length ? "none" : "block";
    document.getElementById("contador-sem-conta").textContent = lista.length ? `${lista.length} dispositivo(s) sem conta` : "";
  } catch (err) {
    document.getElementById("contador-sem-conta").textContent = "Não foi possível carregar a lista: " + err.message;
  }
}

// Superadmin exclui um dispositivo sem conta (item 10 dos testes da 1.4.11)
document.getElementById("corpo-sem-conta").addEventListener("click", async (e) => {
  const btn = e.target.closest('button[data-acao="excluir-sem-conta"]');
  if (!btn) return;
  const id = btn.dataset.id;
  const nome = btn.dataset.nome ? ` (${btn.dataset.nome})` : "";
  if (!confirm(`Excluir o dispositivo ${formatarId(id)}${nome}?\n\n` +
               "Se a máquina der sinal de novo, ela volta para esta lista.")) return;
  try {
    const resp = await fetch(`${API}/devices/sem-conta/${id}`, { method: "DELETE", headers: headersAuth() });
    if (resp.status === 401) { mostrarLogin(); return; }
    const data = await resp.json();
    if (!data.success) { alert(data.error || "Não foi possível excluir."); return; }
    carregarSemConta();
  } catch (err) {
    alert("Não foi possível excluir: " + err.message);
  }
});

// ---- Gerenciar usuários ----

// Item 41: o superadmin vê e cria os admins das empresas; o admin de empresa
// vê e cria os técnicos dele. Ninguém define a senha de outro: o usuário
// recebe um link por e-mail. Usuário não é excluído, só desativado.
let nomeMasterUsuarios = "";
// Menor senha permanente que quem está logado pode dar (vem do servidor)
let senhaMinimaUsuarios = 1;

function abrirModalUsuarios() {
  document.getElementById("overlay-usuarios").style.display = "flex";
  document.getElementById("aviso-lista-usuarios").style.display = "none";
  carregarUsuarios();
}

function fecharModalUsuarios() {
  document.getElementById("overlay-usuarios").style.display = "none";
}
document.getElementById("btn-fechar-usuarios").addEventListener("click", fecharModalUsuarios);

function avisoListaUsuarios(texto, erro) {
  const avisoEl = document.getElementById("aviso-lista-usuarios");
  const erroEl = document.getElementById("erro-lista-usuarios");
  avisoEl.style.display = "none";
  erroEl.style.display = "none";
  if (!texto) return;
  const el = erro ? erroEl : avisoEl;
  el.textContent = texto;
  el.style.display = "block";
}

async function carregarUsuarios() {
  const erroEl = document.getElementById("erro-lista-usuarios");
  erroEl.style.display = "none";
  try {
    const resp = await fetch(`${API}/usuarios`, { headers: headersAuth() });
    if (resp.status === 401) { mostrarLogin(); return; }
    const data = await resp.json();
    if (data.success === false) {
      erroEl.textContent = data.error || "Erro ao carregar usuários.";
      erroEl.style.display = "block";
      return;
    }
    usuarios = data.usuarios || [];
    usuarioSuper = !!data.super;
    nomeMasterUsuarios = data.master_nome || nomeUsuario;
    senhaMinimaUsuarios = data.senha_minima || 1;
    renderizarTabelaUsuarios();
  } catch (err) {
    erroEl.textContent = "Erro ao carregar usuários: " + err.message;
    erroEl.style.display = "block";
  }
}

function situacaoUsuario(u) {
  if (u.ativo === "N") return '<span class="badge-nao">Inativo</span>';
  if (u.aguardando_senha) return '<span class="badge-pendente" title="Ainda não criou a senha pelo link do e-mail">Aguardando senha</span>';
  return '<span class="badge-sim">Ativo</span>';
}

function renderizarTabelaUsuarios() {
  document.getElementById("titulo-lista-usuarios").textContent =
    usuarioSuper ? "Administradores das empresas" : "Técnicos";
  document.getElementById("cabecalho-tabela-usuarios").innerHTML = `
    <tr>
      <th>Nome</th>
      ${usuarioSuper ? "<th>Empresa</th>" : ""}
      <th>E-mail (login)</th>
      <th class="centralizado" title="Número da senha permanente que este usuário usa no MRDesk">Senha permanente</th>
      ${usuarioSuper ? '<th class="centralizado" title="Acessos simultâneos: quantas máquinas a empresa pode acessar ao mesmo tempo">Acessos</th>' : ""}
      <th class="centralizado">Situação</th>
      <th class="centralizado">Último login</th>
      <th class="acoes-linha">Ações</th>
    </tr>`;
  const corpo = document.getElementById("corpo-tabela-usuarios");
  corpo.innerHTML = "";
  usuarios.forEach(u => {
    const tr = document.createElement("tr");
    const opacidade = u.ativo === "N" ? "opacity:0.5;" : "";
    const tituloLink = u.aguardando_senha ? "Reenviar o e-mail para criar a senha" : "Enviar e-mail para redefinir a senha";
    tr.innerHTML = `
      <td style="${opacidade}">${escapeHtml(u.nome)}</td>
      ${usuarioSuper ? `<td style="${opacidade}">${escapeHtml(u.empresa || "—")}</td>` : ""}
      <td style="${opacidade}">${escapeHtml(u.email || "—")}</td>
      <td class="centralizado" style="${opacidade}">${u.senha_permanente ? "Senha " + u.senha_permanente : "—"}</td>
      ${usuarioSuper ? `<td class="centralizado" style="${opacidade}">${u.acessos_simultaneos
        ? `<button type="button" class="link-acessos" data-acao="acessos-usuario" data-id="${u.usuario}" title="Acessos abertos agora / limite. Clique para ver a lista.">${u.acessos_abertos || 0}/${u.acessos_simultaneos}</button>`
        : "—"}</td>` : ""}
      <td class="centralizado" style="${opacidade}">${situacaoUsuario(u)}</td>
      <td class="centralizado" style="${opacidade}">${u.ultimo_login ? formatarDataHora(u.ultimo_login) : "—"}</td>
      <td class="acoes-linha">
        <button title="Editar" data-acao="editar-usuario" data-id="${u.usuario}">${ICONE_EDITAR}</button>
        ${u.ativo === "N" ? "" : `<button title="${tituloLink}" data-acao="link-usuario" data-id="${u.usuario}">${ICONE_EMAIL}</button>`}
      </td>`;
    corpo.appendChild(tr);
  });
}

document.getElementById("corpo-tabela-usuarios").addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;
  const id = btn.dataset.id;
  const acao = btn.dataset.acao;
  const u = usuarios.find(x => String(x.usuario) === String(id));

  if (acao === "editar-usuario") {
    abrirModalUsuario(u);
  }

  if (acao === "link-usuario") {
    const pergunta = u.aguardando_senha
      ? `Reenviar para ${u.email} o e-mail com o link para criar a senha?`
      : `Enviar para ${u.email} um e-mail com o link para redefinir a senha?\n(A senha atual continua valendo até o link ser usado.)`;
    if (!confirm(pergunta)) return;
    btn.disabled = true;
    try {
      const resp = await fetch(`${API}/usuarios/${id}/link`, { method: "POST", headers: headersAuth() });
      if (resp.status === 401) { mostrarLogin(); return; }
      const data = await resp.json();
      avisoListaUsuarios(data.success ? data.aviso : (data.error || "Não foi possível enviar."), !data.success);
    } catch (err) {
      avisoListaUsuarios("Erro de conexão: " + err.message, true);
    } finally {
      btn.disabled = false;
    }
  }
});

document.getElementById("btn-novo-usuario").addEventListener("click", () => abrirModalUsuario(null));

function abrirModalUsuario(u) {
  document.getElementById("erro-modal-usuario").style.display = "none";
  document.getElementById("form-usuario").reset();

  // Tipo e master são definidos pelo servidor a partir de quem está logado;
  // aqui aparecem só como informação (desabilitados).
  const tipo = usuarioSuper ? "Administrador de empresa" : "Técnico (só MRDeskPro)";
  document.getElementById("usuario-tipo").value = tipo;
  document.getElementById("usuario-master").value = nomeMasterUsuarios;
  document.getElementById("campos-usuario-empresa").style.display = usuarioSuper ? "block" : "none";
  document.getElementById("usuario-empresa").required = usuarioSuper;
  document.getElementById("usuario-acessos-simultaneos").required = usuarioSuper;

  // Senha permanente: o superadmin dá da 2 à 5 ao admin da empresa (começa na
  // 2). O admin dá aos técnicos do número dele até o 5, começando no dele.
  // A Senha 1 é fixa da Sysrs: pro admin dela o campo fica travado na 1; pros
  // outros admins a opção Senha 1 nem aparece.
  const contaSysrs = usuarioSuper && !!(u && u.sysrs);
  const menorSenha = usuarioSuper ? (contaSysrs ? 1 : 2) : senhaMinimaUsuarios;
  const senhaPadrao = usuarioSuper ? 2 : senhaMinimaUsuarios;
  document.querySelectorAll("#usuario-senha-permanente option").forEach(o => {
    const fora = Number(o.value) < menorSenha;
    o.disabled = fora;
    o.hidden = fora;
  });
  document.getElementById("usuario-senha-permanente").disabled = contaSysrs;
  document.getElementById("dica-usuario-senha-permanente").textContent = contaSysrs
    ? "A Senha 1 é fixa da Sysrs e não pode ser alterada."
    : usuarioSuper
    ? "Senha que o administrador usa no MRDesk. Os técnicos da empresa usam desta até a Senha 5. A Senha 1 é reservada para a Sysrs."
    : (senhaMinimaUsuarios > 1
        ? `Senha que o técnico usa no MRDesk (da Senha ${senhaMinimaUsuarios} à Senha 5).`
        : "Senha que o técnico usa no MRDesk.");

  const email = document.getElementById("usuario-email");
  const dica = document.getElementById("dica-usuario-email");
  if (u) {
    document.getElementById("titulo-modal-usuario").textContent = usuarioSuper ? "Editar administrador" : "Editar técnico";
    document.getElementById("usuario-id-original").value = u.usuario;
    document.getElementById("usuario-nome").value = u.nome;
    email.value = u.email || "";
    document.getElementById("usuario-empresa").value = u.empresa || "";
    document.getElementById("usuario-senha-permanente").value = String(u.senha_permanente || senhaPadrao);
    document.getElementById("usuario-acessos-simultaneos").value = u.acessos_simultaneos || 1;
    document.getElementById("usuario-observacoes").value = u.observacoes || "";
    document.getElementById("usuario-ativo").checked = u.ativo !== "N";
    // E-mail fixo depois de criada a senha. Exceções: aguardando senha
    // (corrigir digitação) e o superadmin trocando o admin da empresa.
    email.disabled = !(u.aguardando_senha || usuarioSuper);
    if (u.aguardando_senha) {
      dica.dataset.curto = "Corrija se estiver errado";
      dica.textContent = "Ainda sem senha: se o e-mail estiver errado, corrija e um novo link será enviado.";
    } else if (usuarioSuper) {
      dica.dataset.curto = "Trocar passa a empresa para outra pessoa";
      dica.textContent = "Trocar o e-mail passa a empresa para outra pessoa: a senha atual deixa de valer e o novo e-mail recebe o link.";
    } else {
      dica.dataset.curto = "Não muda depois de criada a senha";
      dica.textContent = "O e-mail não muda depois de criada a senha. Para outra pessoa, crie um novo técnico e desative este.";
    }
  } else {
    document.getElementById("titulo-modal-usuario").textContent = usuarioSuper ? "Novo administrador de empresa" : "Novo técnico";
    document.getElementById("usuario-id-original").value = "";
    document.getElementById("usuario-senha-permanente").value = String(senhaPadrao);
    document.getElementById("usuario-acessos-simultaneos").value = 1;
    document.getElementById("usuario-ativo").checked = true;
    email.disabled = false;
    dica.dataset.curto = "Recebe o link para criar a senha";
    dica.textContent = "O usuário recebe neste e-mail um link para criar a própria senha.";
  }

  document.getElementById("overlay-form-usuario").style.display = "flex";
}

function fecharModalUsuario() {
  document.getElementById("overlay-form-usuario").style.display = "none";
}
document.getElementById("btn-cancelar-form-usuario").addEventListener("click", fecharModalUsuario);

document.getElementById("form-usuario").addEventListener("submit", async (e) => {
  e.preventDefault();
  const idOriginal = document.getElementById("usuario-id-original").value;
  const erroEl = document.getElementById("erro-modal-usuario");
  erroEl.style.display = "none";

  // "admin" e "master" não são enviados: o servidor decide por quem está logado.
  const corpo = {
    nome: document.getElementById("usuario-nome").value.trim(),
    email: document.getElementById("usuario-email").value.trim(),
    observacoes: document.getElementById("usuario-observacoes").value.trim(),
    ativo: document.getElementById("usuario-ativo").checked ? "S" : "N"
  };
  corpo.senha_permanente = Number(document.getElementById("usuario-senha-permanente").value);
  if (usuarioSuper) {
    corpo.empresa = document.getElementById("usuario-empresa").value.trim();
    corpo.acessos_simultaneos = Number(document.getElementById("usuario-acessos-simultaneos").value);
  }

  const btn = e.target.querySelector('button[type="submit"]');
  btn.disabled = true;
  try {
    const editando = !!idOriginal;
    const resp = await fetch(editando ? `${API}/usuarios/${idOriginal}` : `${API}/usuarios`, {
      method: editando ? "PUT" : "POST", headers: headersAuth(), body: JSON.stringify(corpo)
    });
    if (resp.status === 401) { mostrarLogin(); return; }
    const data = await resp.json();
    if (data.success) {
      fecharModalUsuario();
      await carregarUsuarios();
      avisoListaUsuarios(data.aviso || "", !!data.email_falhou);
    } else {
      erroEl.textContent = data.error || "Erro ao salvar.";
      erroEl.style.display = "block";
    }
  } catch (err) {
    erroEl.textContent = "Erro de conexão: " + err.message;
    erroEl.style.display = "block";
  } finally {
    btn.disabled = false;
  }
});


// ---- Técnicos autorizados (item 6A - só admin) ----

function abrirModalTecnicos() {
  document.getElementById("overlay-tecnicos").style.display = "flex";
  carregarTecnicos();
}

function fecharModalTecnicos() {
  document.getElementById("overlay-tecnicos").style.display = "none";
}
document.getElementById("btn-fechar-tecnicos").addEventListener("click", fecharModalTecnicos);

async function carregarTecnicos() {
  const erroEl = document.getElementById("erro-lista-tecnicos");
  erroEl.style.display = "none";
  try {
    const resp = await fetch(`${API}/tecnicos`, { headers: headersAuth() });
    if (resp.status === 401) { mostrarLogin(); return; }
    const data = await resp.json();
    if (!data.success) {
      erroEl.textContent = data.error || "Erro ao carregar técnicos.";
      erroEl.style.display = "block";
      return;
    }
    tecnicos = data.tecnicos || [];
    renderizarTabelaTecnicos();
  } catch (err) {
    erroEl.textContent = "Erro ao carregar técnicos: " + err.message;
    erroEl.style.display = "block";
  }
}

function renderizarTabelaTecnicos() {
  const corpo = document.getElementById("corpo-tabela-tecnicos");
  corpo.innerHTML = "";
  if (tecnicos.length === 0) {
    corpo.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--texto-secundario);">Nenhum MRDeskPro cadastrado.</td></tr>';
    return;
  }
  tecnicos.forEach(t => {
    // Autorizado de fato = linha ativa E usuario dono ativo
    const autorizado = t.ativo === "S" && t.usuario_ativo === "S";
    const opacidade = autorizado ? "" : "opacity:0.5;";
    const textoAtivo = t.ativo !== "S" ? "Não" : (t.usuario_ativo !== "S" ? "Não (usuário inativo)" : "Sim");
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td style="${opacidade}">${escapeHtml(t.usuario_nome)}</td>
      <td style="${opacidade}text-align:right;font-family:monospace;">${formatarId(t.dispositivo)}</td>
      <td style="${opacidade}">${escapeHtml(t.descricao || "—")}</td>
      <td class="centralizado" style="${opacidade}">${t.ultima_vez_online ? formatarDataHora(t.ultima_vez_online) : "—"}</td>
      <td class="centralizado" style="${opacidade}"><span class="${autorizado ? 'badge-sim' : 'badge-nao'}">${textoAtivo}</span></td>
      <td class="acoes-linha">
        <button title="Editar" data-acao="editar-tecnico" data-id="${escapeHtml(t.dispositivo)}">${ICONE_EDITAR}</button>
      </td>`;
    corpo.appendChild(tr);
  });
}

document.getElementById("corpo-tabela-tecnicos").addEventListener("click", (e) => {
  const btn = e.target.closest("button");
  if (!btn || btn.dataset.acao !== "editar-tecnico") return;
  const t = tecnicos.find(x => x.dispositivo === btn.dataset.id);
  if (t) abrirModalTecnico(t);
});

document.getElementById("btn-novo-tecnico").addEventListener("click", () => abrirModalTecnico(null));

async function preencherComboTecnicos(usuarioSelecionado) {
  const combo = document.getElementById("tecnico-usuario");
  combo.innerHTML = "";
  try {
    const resp = await fetch(`${API}/usuarios?incluir_proprio=1`, { headers: headersAuth() });
    const data = await resp.json();
    const lista = (data.usuarios || []).filter(u => u.ativo !== "N" || String(u.usuario) === String(usuarioSelecionado));
    const vazio = document.createElement("option");
    vazio.value = "";
    vazio.textContent = "Selecione...";
    combo.appendChild(vazio);
    lista.forEach(u => {
      const opt = document.createElement("option");
      opt.value = u.usuario;
      opt.textContent = u.nome + (u.ativo === "N" ? " (inativo)" : "");
      combo.appendChild(opt);
    });
    combo.value = usuarioSelecionado != null ? String(usuarioSelecionado) : "";
  } catch (err) {
    const erroEl = document.getElementById("erro-modal-tecnico");
    erroEl.textContent = "Erro ao carregar usuários: " + err.message;
    erroEl.style.display = "block";
  }
}

function abrirModalTecnico(t) {
  document.getElementById("erro-modal-tecnico").style.display = "none";
  document.getElementById("form-tecnico").reset();
  if (t) {
    document.getElementById("titulo-modal-tecnico").textContent = "Editar MRDeskPro";
    document.getElementById("tecnico-dispositivo-original").value = t.dispositivo;
    document.getElementById("tecnico-dispositivo").value = formatarId(t.dispositivo);
    document.getElementById("tecnico-descricao").value = t.descricao || "";
    document.getElementById("tecnico-ativo").checked = t.ativo === "S";
  } else {
    document.getElementById("titulo-modal-tecnico").textContent = "Novo MRDeskPro";
    document.getElementById("tecnico-dispositivo-original").value = "";
    document.getElementById("tecnico-ativo").checked = true;
  }
  preencherComboTecnicos(t ? t.usuario : null);
  document.getElementById("overlay-form-tecnico").style.display = "flex";
}

function fecharModalTecnico() {
  document.getElementById("overlay-form-tecnico").style.display = "none";
}
document.getElementById("btn-cancelar-form-tecnico").addEventListener("click", fecharModalTecnico);

document.getElementById("form-tecnico").addEventListener("submit", async (e) => {
  e.preventDefault();
  const original = document.getElementById("tecnico-dispositivo-original").value;
  const dispositivo = document.getElementById("tecnico-dispositivo").value.replace(/\s/g, "");
  const usuario = document.getElementById("tecnico-usuario").value;
  const descricao = document.getElementById("tecnico-descricao").value.trim();
  const ativo = document.getElementById("tecnico-ativo").checked ? "S" : "N";
  const erroEl = document.getElementById("erro-modal-tecnico");
  erroEl.style.display = "none";

  if (!usuario) {
    erroEl.textContent = "Selecione o técnico.";
    erroEl.style.display = "block";
    return;
  }

  const corpo = { dispositivo, usuario: Number(usuario), descricao, ativo };
  try {
    const resp = await fetch(original ? `${API}/tecnicos/${encodeURIComponent(original)}` : `${API}/tecnicos`, {
      method: original ? "PUT" : "POST", headers: headersAuth(), body: JSON.stringify(corpo)
    });
    const data = await resp.json();
    if (data.success) {
      fecharModalTecnico();
      carregarTecnicos();
    } else {
      erroEl.textContent = data.error || "Erro ao salvar.";
      erroEl.style.display = "block";
    }
  } catch (err) {
    erroEl.textContent = "Erro de conexão: " + err.message;
    erroEl.style.display = "block";
  }
});

// ---- Textos explicativos dos campos (regra de tela, 04/10/2026) ----
// Nos formulários, a explicação de um campo não ocupa linha: vira o texto de
// fundo do campo vazio (placeholder) e a dica que aparece ao parar o mouse no
// campo ou no nome dele (title) - assim continua disponível depois de
// preenchido. Basta pôr um <div class="dica-campo"> logo depois do campo; o
// texto pode ser trocado por código (ex.: dica do e-mail) que a dica acompanha.
function aplicarDicaDoCampo(dica) {
  let campo = dica.previousElementSibling;
  if (campo && !campo.matches("input, select, textarea")) campo = campo.querySelector("input, select, textarea");
  if (!campo) return;
  const texto = dica.textContent.trim();
  campo.title = texto;
  // fundo do campo: a versão curta (data-curto), pra não cortar no meio
  if (campo.matches("input, textarea")) campo.placeholder = dica.dataset.curto || texto;
  // o nome do campo (label logo antes) mostra a mesma dica
  let rotulo = (campo.closest(".campo-senha") || campo).previousElementSibling;
  if (rotulo && rotulo.tagName === "LABEL") rotulo.title = texto;
}
document.querySelectorAll("form div.dica-campo").forEach(dica => {
  aplicarDicaDoCampo(dica);
  new MutationObserver(() => aplicarDicaDoCampo(dica))
    .observe(dica, { childList: true, characterData: true, subtree: true, attributes: true, attributeFilter: ["data-curto"] });
});


// ---- Acessos abertos (limite de acessos simultâneos da empresa) ----
// Contador "abertos/limite" no topo (admin de empresa) e janela com a lista.
// O superadmin abre a mesma janela pela coluna "Acessos" de Gerenciar contas.
// Não é ao vivo: atualiza junto com a lista de dispositivos (ao abrir, F5 e a
// cada 5 min) e no botão Atualizar da janela.
let contaDosAcessos = null; // superadmin: conta que a janela está mostrando

async function buscarAcessos(conta) {
  const resp = await fetch(`${API}/acessos${conta ? "?conta=" + conta : ""}`, { headers: headersAuth() });
  if (resp.status === 401) { mostrarLogin(); return null; }
  return resp.json();
}

function mostrarContadorDeAcessos(data) {
  const btn = document.getElementById("btn-acessos");
  document.getElementById("contador-acessos").textContent = `Acessos ${data.abertos}/${data.limite}`;
  btn.classList.toggle("no-limite", data.abertos >= data.limite);
  btn.style.display = "flex";
}

async function carregarContadorDeAcessos() {
  const btn = document.getElementById("btn-acessos");
  if (usuarioSuper) { btn.style.display = "none"; return; }
  try {
    const data = await buscarAcessos(null);
    if (data && data.success) mostrarContadorDeAcessos(data);
  } catch (_) {}
}

async function carregarJanelaDeAcessos() {
  const erroEl = document.getElementById("erro-acessos");
  const corpo = document.getElementById("corpo-tabela-acessos");
  erroEl.style.display = "none";
  try {
    const data = await buscarAcessos(contaDosAcessos);
    if (!data) return;
    if (!data.success) throw new Error(data.error || "Erro ao carregar os acessos.");
    document.getElementById("titulo-acessos").textContent =
      `Acessos abertos${contaDosAcessos && data.empresa ? " - " + data.empresa : ""} (${data.abertos}/${data.limite})`;
    if (!contaDosAcessos) mostrarContadorDeAcessos(data);
    corpo.innerHTML = data.acessos.length ? "" : '<tr><td colspan="5" class="centralizado">Nenhum acesso aberto.</td></tr>';
    data.acessos.forEach(a => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${escapeHtml(a.tecnico || formatarId(a.origem))}</td>
        <td style="font-family:monospace;">${escapeHtml(formatarId(a.dispositivo))}</td>
        <td>${escapeHtml(a.apelido || "—")}</td>
        <td>${escapeHtml(a.cliente || "—")}</td>
        <td class="centralizado">${formatarDataHora(a.inicio)}</td>`;
      corpo.appendChild(tr);
    });
  } catch (err) {
    erroEl.textContent = err.message;
    erroEl.style.display = "block";
  }
}

function abrirJanelaDeAcessos(conta) {
  contaDosAcessos = conta || null;
  document.getElementById("corpo-tabela-acessos").innerHTML = "";
  document.getElementById("titulo-acessos").textContent = "Acessos abertos";
  document.getElementById("overlay-acessos").style.display = "flex";
  carregarJanelaDeAcessos();
}

document.getElementById("btn-acessos").addEventListener("click", () => abrirJanelaDeAcessos(null));
document.getElementById("btn-atualizar-acessos").addEventListener("click", carregarJanelaDeAcessos);
document.getElementById("btn-fechar-acessos").addEventListener("click", () => {
  document.getElementById("overlay-acessos").style.display = "none";
  if (contaDosAcessos) carregarUsuarios(); // a coluna "Acessos" da lista de contas acompanha
});
document.getElementById("corpo-tabela-usuarios").addEventListener("click", (e) => {
  const btn = e.target.closest('button[data-acao="acessos-usuario"]');
  if (btn) abrirJanelaDeAcessos(Number(btn.dataset.id));
});
