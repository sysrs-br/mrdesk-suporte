const API = "/api";
let token = localStorage.getItem("mrdesk_token");
let nomeUsuario = localStorage.getItem("mrdesk_nome");
let usuarioAdmin = localStorage.getItem("mrdesk_admin") === "1";
let usuarioExcluirDevice = localStorage.getItem("mrdesk_excluir_device") === "1";
let dispositivos = [];
let catalogos = [];
let catalogoAtual = null;
let idParaMover = null;
let usuarios = [];

const ICONE_ARQUIVOS = '<svg class="icon" viewBox="0 0 24 24"><path d="M4 8h13M13 5l4 3-4 3"/><path d="M20 16H7M11 13l-4 3 4 3"/></svg>';
const ICONE_CONECTAR = '<svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M8 12h7M12 9l3 3-3 3"/></svg>';
const ICONE_PONTOS = '<svg class="icon" viewBox="0 0 24 24" style="stroke-width:2.5;"><circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/></svg>';
const ICONE_CATALOGO = '<svg class="icon" viewBox="0 0 24 24"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>';
const ICONE_EDITAR = '<svg class="icon" viewBox="0 0 24 24"><path d="M11 5H6a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-5"/><path d="M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4z"/></svg>';
const ICONE_REMOVER = '<svg class="icon" viewBox="0 0 24 24"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M10 11v6M14 11v6"/></svg>';
const ICONE_MOVER = '<svg class="icon" viewBox="0 0 24 24"><path d="M4 20h9"/><path d="M4 4h6v6H4z"/><path d="M15 7h6M18 4l3 3-3 3"/></svg>';

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

function mostrarApp() {
  document.getElementById("tela-login").style.display = "none";
  document.getElementById("app").style.display = "block";
  document.getElementById("nome-usuario").textContent = nomeUsuario;
  document.getElementById("btn-gerenciar-usuarios").style.display = usuarioAdmin ? "flex" : "none";
  document.getElementById("separador-menu-usuario").style.display = usuarioAdmin ? "block" : "none";
  document.getElementById("btn-menu-excluir-dispositivo").style.display = (usuarioAdmin || usuarioExcluirDevice) ? "flex" : "none";
  carregarCatalogos();
  carregarTrafego();
}

// ---- Gráficos do cabeçalho: tráfego de saída (limite de 10 TB/mês do plano
// da Oracle), espaço em disco da VM e sessões que passaram pelo relay ----
let timerTrafego = null;

function formatarPct(pct) {
  return pct.toLocaleString("pt-BR", { maximumFractionDigits: 2 });
}

function formatarGB(bytes) {
  // Mesma unidade do "df -h" (GiB), pra bater com o que aparece no servidor.
  return (bytes / 1024 ** 3).toLocaleString("pt-BR", { maximumFractionDigits: 1 });
}

async function atualizarPizza(idElemento, rota, montarHint, avisarAcimaDe80 = true) {
  const el = document.getElementById(idElemento);
  try {
    const resp = await fetch(`${API}/${rota}`, { headers: headersAuth() });
    if (resp.status === 401) return;
    const data = await resp.json();
    if (data.success) {
      const pct = Math.min(100, Math.max(0, Number(data.percentual) || 0));
      el.style.setProperty("--pct", pct);
      el.classList.toggle("alerta", avisarAcimaDe80 && pct >= 80);
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

function mostrarLogin() {
  document.getElementById("tela-login").style.display = "flex";
  document.getElementById("app").style.display = "none";
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

if (token) { mostrarApp(); } else { mostrarLogin(); }

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
      usuarioExcluirDevice = !!data.excluir_device;
      localStorage.setItem("mrdesk_token", token);
      localStorage.setItem("mrdesk_nome", nomeUsuario);
      localStorage.setItem("mrdesk_admin", usuarioAdmin ? "1" : "0");
      localStorage.setItem("mrdesk_excluir_device", usuarioExcluirDevice ? "1" : "0");
      localStorage.setItem("mrdesk_ultimo_usuario", usuario);
      mostrarApp();
    } else {
      erroEl.textContent = data.error || "Usuário ou senha inválidos.";
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
  localStorage.removeItem("mrdesk_nome");
  localStorage.removeItem("mrdesk_admin");
  localStorage.removeItem("mrdesk_excluir_device");
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

document.getElementById("btn-alterar-senha").addEventListener("click", () => {
  document.getElementById("menu-usuario-lista").classList.remove("aberto");
  abrirModalAlterarSenha();
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

  if (senhaNova.length < 6) {
    erroEl.textContent = "A nova senha deve ter pelo menos 6 caracteres.";
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
      fecharModalAlterarSenha();
      alert("Senha alterada com sucesso.");
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
      document.getElementById("combo-catalogo-lista").classList.remove("aberto");
      renderizarComboCatalogos();
      carregarDispositivos();
    });
    lista.appendChild(item);
  });

  const sep1 = document.createElement("div");
  sep1.className = "combo-catalogo-separador";
  lista.appendChild(sep1);

  const adicionar = document.createElement("div");
  adicionar.className = "combo-catalogo-item combo-catalogo-especial";
  adicionar.innerHTML = `<svg class="icon" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M8 2v4M16 2v4M3 10h18"/><path d="M12 14v4M10 16h4"/></svg><span>Adicionar dispositivo</span>`;
  adicionar.addEventListener("click", () => {
    document.getElementById("combo-catalogo-lista").classList.remove("aberto");
    abrirModal(null);
  });
  lista.appendChild(adicionar);

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
}

document.getElementById("combo-catalogo-btn").addEventListener("click", (e) => {
  e.stopPropagation();
  document.getElementById("combo-catalogo-lista").classList.toggle("aberto");
});
document.addEventListener("click", () => {
  document.getElementById("combo-catalogo-lista").classList.remove("aberto");
  document.getElementById("menu-usuario-lista").classList.remove("aberto");
  fecharMenuFlutuante();
});

// ESC fecha o menu do usuário, o menu de catálogo e o menu flutuante de ações da linha.
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    document.getElementById("combo-catalogo-lista").classList.remove("aberto");
    document.getElementById("menu-usuario-lista").classList.remove("aberto");
    fecharMenuFlutuante();
  }
});

async function carregarDispositivos() {
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
    renderizarTabela();
  } catch (err) {
    alert("Erro ao carregar dispositivos: " + err.message);
  }
}

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

function renderizarTabela() {
  const termoBruto = document.getElementById("busca").value.toLowerCase();
  // Se o texto digitado for so numeros e espacos (ex: "207 575 694"
  // colado com a formatacao), remove os espacos antes de comparar
  // com o ID puro. Buscas por texto (cliente/apelido) so recebem trim.
  const apenasNumerosEEspacos = /^[0-9\s]+$/.test(termoBruto.trim()) && termoBruto.trim() !== "";
  const termo = apenasNumerosEEspacos ? termoBruto.replace(/\s+/g, "") : termoBruto.trim();

  const filtrados = dispositivos.filter(d =>
    d.cliente.toLowerCase().includes(termo) ||
    d.apelido.toLowerCase().includes(termo) ||
    d.id.includes(termo)
  );

  const corpo = document.getElementById("corpo-tabela");
  corpo.innerHTML = "";

  filtrados.forEach(d => {
    const tr = document.createElement("tr");
    tr.className = "linha-dispositivo";
    tr.dataset.id = d.id;
    const opacidadeConteudo = d.ativo === "N" ? "opacity:0.5;" : "";

    let statusClasse = "";
    if (d.online === true) statusClasse = "online";
    else if (d.online === false) statusClasse = "offline";

    const tempoDecorrido = calcularTempoDecorrido(d.ultima_vez_online, d.online);

    tr.innerHTML = `
      <td class="col-status-conectar" style="${opacidadeConteudo}">
        <div class="status-conectar-wrap">
          <span class="bolinha-status ${statusClasse}" title="${statusClasse === 'online' ? 'On-line' : statusClasse === 'offline' ? 'Off-line' : 'Status desconhecido'}"></span>
          <button class="btn-conectar-icone" title="Conectar" data-acao="conectar" data-id="${d.id}">${ICONE_CONECTAR}</button>
        </div>
      </td>
      <td style="${opacidadeConteudo}">${escapeHtml(d.cliente)}</td>
      <td style="${opacidadeConteudo}">${escapeHtml(d.apelido)}</td>
      <td class="id-mono" style="${opacidadeConteudo}">${formatarId(d.id)}</td>
      <td class="data-centralizada" style="${opacidadeConteudo}">
        ${formatarDataHora(d.ultima_vez_online)}
        ${tempoDecorrido ? `<div style="font-size:11px;font-style:italic;color:var(--texto-secundario);">${tempoDecorrido}</div>` : ""}
      </td>
      <td class="acoes-linha">
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
// Quando o texto da busca é um ID completo (9 ou 10 dígitos) e esse ID não
// aparece na lista (catálogo ou filtros escondendo, ou ID não cadastrado),
// mostra o botão "Acessar" ao lado da busca. O hint explica o que esconde o
// dispositivo, comparando com o catálogo e os filtros marcados agora.
let idBotaoAcessar = null;
let timerLocalizar = null;
// Resultado da última consulta: { id, erro, encontrado, device }
let localizado = null;

function atualizarBotaoAcessar(idDigitado, filtrados) {
  const btn = document.getElementById("btn-acessar-id");
  const idCompleto = /^\d{9,10}$/.test(idDigitado);
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
    hint = `${d.cliente} — ${d.apelido}`;
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

function atualizarVisibilidadeBotaoLimpar() {
  const temTexto = document.getElementById("busca").value.length > 0;
  document.getElementById("btn-limpar-busca").style.display = temTexto ? "block" : "none";
}

document.getElementById("busca").addEventListener("input", () => {
  renderizarTabela();
  atualizarVisibilidadeBotaoLimpar();
});

document.getElementById("btn-limpar-busca").addEventListener("click", () => {
  const campo = document.getElementById("busca");
  campo.value = "";
  campo.focus();
  renderizarTabela();
  atualizarVisibilidadeBotaoLimpar();
});

async function conectar(id, modo) {
  try {
    const resp = await fetch(`${API}/devices/${id}/connect?mode=${modo}`, { headers: headersAuth() });
    const data = await resp.json();
    if (data.success) {
      window.location.href = data.link;
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
      const alturaEstimada = 130;
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
    if (confirm(`Confirma a exclusão do dispositivo "${dev.cliente}" (${dev.apelido})?`)) {
      const resp = await fetch(`${API}/devices/${id}`, { method: "DELETE", headers: headersAuth() });
      const data = await resp.json();
      if (data.success) {
        carregarDispositivos();
      } else {
        alert("Erro ao excluir: " + data.error);
      }
    }
  }

  if (acao === "mover") {
    abrirModalMover(id);
  }

  if (acao === "auditoria") {
    abrirModalAuditoria(id);
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

let idParaAuditoria = null;

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
  corpo.innerHTML = "<tr><td colspan=\"5\">Carregando...</td></tr>";

  try {
    const resp = await fetch(
      `${API}/devices/${idParaAuditoria}/auditoria?inicio=${inicio}&fim=${fim}`,
      { headers: headersAuth() }
    );
    if (resp.status === 401) { mostrarLogin(); return; }
    const data = await resp.json();

    if (!data.success) {
      corpo.innerHTML = `<tr><td colspan="5">Erro ao carregar: ${data.error || ""}</td></tr>`;
      return;
    }

    if (data.registros.length === 0) {
      corpo.innerHTML = "<tr><td colspan=\"5\">Nenhuma conexão encontrada no período.</td></tr>";
      return;
    }

    corpo.innerHTML = "";
    data.registros.forEach((r) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${formatarDataHora(r.inicio)}</td>
        <td>${formatarDuracao(r.duracao_segundos)}</td>
        <td>${r.nome || "-"}</td>
        <td>${r.tipo || "-"}</td>
        <td>${r.ip || "-"}</td>
      `;
      corpo.appendChild(tr);
    });
  } catch (err) {
    corpo.innerHTML = `<tr><td colspan="5">Erro ao carregar: ${err.message}</td></tr>`;
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

function abrirModal(dev) {
  document.getElementById("erro-modal").style.display = "none";
  document.getElementById("form-modal").reset();

  if (dev) {
    document.getElementById("titulo-modal").textContent = "Editar dispositivo";
    document.getElementById("modal-id-original").value = dev.id;
    document.getElementById("modal-id").value = formatarId(dev.id);
    document.getElementById("modal-id").disabled = true;
    document.getElementById("modal-apelido").value = dev.apelido;
    document.getElementById("modal-cliente").value = dev.cliente;
    document.getElementById("modal-ativo").checked = dev.ativo !== "N";
    document.getElementById("modal-servidor").checked = dev.servidor === "S";
  } else {
    document.getElementById("titulo-modal").textContent = "Adicionar dispositivo";
    document.getElementById("modal-id-original").value = "";
    document.getElementById("modal-id").disabled = false;
    document.getElementById("modal-ativo").checked = true;
    document.getElementById("modal-servidor").checked = false;
  }

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

  const editando = !!idOriginal;

  try {
    let resp;
    if (editando) {
      resp = await fetch(`${API}/devices/${idOriginal}`, {
        method: "PUT", headers: headersAuth(),
        body: JSON.stringify({ apelido, cliente, ativo, servidor })
      });
    } else {
      resp = await fetch(`${API}/devices`, {
        method: "POST", headers: headersAuth(),
        body: JSON.stringify({ id, apelido, cliente, servidor, catalogo: catalogoAtual.catalogo })
      });
    }
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

// ---- Gerenciar usuários ----

function abrirModalUsuarios() {
  document.getElementById("overlay-usuarios").style.display = "flex";
  carregarUsuarios();
}

function fecharModalUsuarios() {
  document.getElementById("overlay-usuarios").style.display = "none";
}
document.getElementById("btn-fechar-usuarios").addEventListener("click", fecharModalUsuarios);

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
    usuarios = data.usuarios || data || [];
    renderizarTabelaUsuarios();
  } catch (err) {
    erroEl.textContent = "Erro ao carregar usuários: " + err.message;
    erroEl.style.display = "block";
  }
}

function renderizarTabelaUsuarios() {
  const corpo = document.getElementById("corpo-tabela-usuarios");
  corpo.innerHTML = "";
  usuarios.forEach(u => {
    const tr = document.createElement("tr");
    const opacidade = u.ativo === "N" ? "opacity:0.5;" : "";
    tr.innerHTML = `
      <td style="${opacidade}">${escapeHtml(u.nome)}</td>
      <td style="${opacidade}">${escapeHtml(u.email || "—")}</td>
      <td class="centralizado" style="${opacidade}"><span class="${u.admin === 'S' ? 'badge-sim' : 'badge-nao'}">${u.admin === 'S' ? 'Sim' : 'Não'}</span></td>
      <td class="centralizado" style="${opacidade}"><span class="${u.excluir_device === 'S' ? 'badge-sim' : 'badge-nao'}">${u.excluir_device === 'S' ? 'Sim' : 'Não'}</span></td>
      <td class="centralizado" style="${opacidade}"><span class="${u.ativo !== 'N' ? 'badge-sim' : 'badge-nao'}">${u.ativo !== 'N' ? 'Sim' : 'Não'}</span></td>
      <td class="acoes-linha">
        <button title="Editar" data-acao="editar-usuario" data-id="${u.usuario}">${ICONE_EDITAR}</button>
        ${u.admin === 'S' ? '' : `<button title="Remover" data-acao="excluir-usuario" data-id="${u.usuario}">${ICONE_REMOVER}</button>`}
      </td>`;
    corpo.appendChild(tr);
  });
}

document.getElementById("corpo-tabela-usuarios").addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;
  const id = btn.dataset.id;
  const acao = btn.dataset.acao;

  if (acao === "editar-usuario") {
    const u = usuarios.find(x => String(x.usuario) === String(id));
    abrirModalUsuario(u);
  }

  if (acao === "excluir-usuario") {
    const u = usuarios.find(x => String(x.usuario) === String(id));
    if (confirm(`Confirma a exclusão do usuário "${u.nome}"?`)) {
      try {
        const resp = await fetch(`${API}/usuarios/${id}`, { method: "DELETE", headers: headersAuth() });
        const data = await resp.json();
        if (data.success) {
          carregarUsuarios();
        } else {
          alert("Erro ao excluir: " + data.error);
        }
      } catch (err) {
        alert("Erro ao excluir: " + err.message);
      }
    }
  }
});

document.getElementById("btn-novo-usuario").addEventListener("click", () => abrirModalUsuario(null));

function abrirModalUsuario(u) {
  document.getElementById("erro-modal-usuario").style.display = "none";
  document.getElementById("form-usuario").reset();

  if (u) {
    document.getElementById("titulo-modal-usuario").textContent = "Editar usuário";
    document.getElementById("usuario-id-original").value = u.usuario;
    document.getElementById("usuario-nome").value = u.nome;
    document.getElementById("usuario-senha").required = false;
    document.getElementById("label-senha-opcional").style.display = "inline";
    document.getElementById("usuario-email").value = u.email || "";
    document.getElementById("usuario-observacoes").value = u.observacoes || "";
    document.getElementById("usuario-excluir-device").checked = u.excluir_device === "S";
    document.getElementById("usuario-ativo").checked = u.ativo !== "N";
  } else {
    document.getElementById("titulo-modal-usuario").textContent = "Novo usuário";
    document.getElementById("usuario-id-original").value = "";
    document.getElementById("usuario-senha").required = true;
    document.getElementById("label-senha-opcional").style.display = "none";
    document.getElementById("usuario-excluir-device").checked = false;
    document.getElementById("usuario-ativo").checked = true;
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
  const nome = document.getElementById("usuario-nome").value.trim();
  const senha = document.getElementById("usuario-senha").value;
  const email = document.getElementById("usuario-email").value.trim();
  const observacoes = document.getElementById("usuario-observacoes").value.trim();
  const excluir_device = document.getElementById("usuario-excluir-device").checked ? "S" : "N";
  const ativo = document.getElementById("usuario-ativo").checked ? "S" : "N";
  const erroEl = document.getElementById("erro-modal-usuario");
  erroEl.style.display = "none";

  const editando = !!idOriginal;
  const corpo = { nome, email, observacoes, excluir_device, ativo };
  if (senha) corpo.senha = senha;

  try {
    let resp;
    if (editando) {
      resp = await fetch(`${API}/usuarios/${idOriginal}`, {
        method: "PUT", headers: headersAuth(), body: JSON.stringify(corpo)
      });
    } else {
      resp = await fetch(`${API}/usuarios`, {
        method: "POST", headers: headersAuth(), body: JSON.stringify(corpo)
      });
    }
    const data = await resp.json();
    if (data.success) {
      fecharModalUsuario();
      carregarUsuarios();
    } else {
      erroEl.textContent = data.error || "Erro ao salvar.";
      erroEl.style.display = "block";
    }
  } catch (err) {
    erroEl.textContent = "Erro de conexão: " + err.message;
    erroEl.style.display = "block";
  }
});
