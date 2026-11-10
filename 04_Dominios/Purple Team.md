---
title: "Purple Team"
tags: [purple-team, mitre-attack, atomic-red-team, sigma, detection-engineering]
status: backlog
---

# 🟣 Purple Team

**Relacionado:** [[02_Ferramentas_Stack/XM Cyber]] · [[04_Dominios/Threat Intel & Exploit Feed]] · [[02_Ferramentas_Stack/OpenCTI]]

## 💡 Ideia
Red (emula o ataque) e Blue (detecta/responde) trabalhando **juntos e em ciclo**. O objetivo é melhorar a detecção, não "vencer".

## 🔁 Ciclo
1. **CTI** escolhe o adversário relevante (OpenCTI/MISP → TTPs)
2. Mapear as TTPs no **MITRE ATT&CK** (ATT&CK Navigator)
3. **Emular** a técnica (Atomic Red Team / Caldera)
4. **Verificar** se o SIEM/EDR detectou
5. Criar ou ajustar a **detecção** (Sigma) → repetir

## 🧰 Ferramentas

| Função | Ferramenta |
|---|---|
| Emulação | Atomic Red Team, MITRE Caldera, Stratus Red Team (cloud) |
| BAS comercial | XM Cyber (attack path), SafeBreach |
| Detecção as code | Sigma, sigma-cli |
| Planejamento | ATT&CK Navigator, VECTR |

```powershell
Invoke-AtomicTest T1003.001 -ShowDetails   # LSASS dump (o mesmo cenário da nota do XM Cyber)
Invoke-AtomicTest T1003.001
```

## 📊 Métricas
% das técnicas priorizadas com detecção · tempo até detectar (MTTD) · cobertura no ATT&CK

## ✅ Próximos passos
- [ ] Lab Windows + Atomic Red Team + Sysmon
- [ ] Converter 3 cenários da nota do XM Cyber em regras Sigma
