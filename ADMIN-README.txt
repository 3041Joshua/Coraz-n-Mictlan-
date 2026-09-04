CORAZÓN MICTLAN — PANEL ADMIN

1. Este proyecto usa Netlify Functions + Netlify Blobs.
2. Sube este proyecto a GitHub.
3. Conecta el repositorio a Netlify.
4. En Netlify -> Site configuration -> Environment variables crea:
   ADMIN_PASSWORD = una contraseña fuerte
5. Haz un deploy.
6. Abre https://TU-DOMINIO/admin/

IMPORTANTE:
- La computadora NO necesita estar encendida.
- Las fotos y datos se guardan en Netlify Blobs.
- Si editas un evento y NO eliges una nueva foto, la imagen anterior se conserva.
- El sitio público consulta los eventos desde la función.

PRÓXIMO PASO:
- Ajustar el diseño del panel al estilo visual de Corazón Mictlan.
- Hacer que los cuadros actuales del inicio también se carguen desde el panel.
- Agregar campos específicos según cada cuadro.
