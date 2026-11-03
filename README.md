# Ritmo

*Tu tiempo tiene ritmo.* App móvil (PWA) que reúne tu Google Calendar, tus Tareas y los correos con citas o pagos, y te ayuda a ordenar el día.

- Calendario con filtros por tipo de evento (clases, entrevistas, pagos…)
- Recordatorios amables (notificaciones push)
- Asistente con IA (Gemini)
- Rutas sugeridas de TransMilenio y SITP (Google Routes API)
- Tiempo en apps, alimentado por Atajos de iPhone o Tasker

Stack: Node 20 · Express · PostgreSQL · Google OAuth.

```bash
cp .env.example .env   # completa las variables
npm install
npm run dev            # http://localhost:3000
```
