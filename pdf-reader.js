async function extractTextFromPDF(file) {
    const arrayBuffer = await file.arrayBuffer();
    const pdfjsLib = window['pdfjs-dist/build/pdf'];
    pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

    const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
    let fullText = "";

    for (let i = 1; i <= pdf.numPages; i++) {
        const page = await pdf.getPage(i);
        const content = await page.getTextContent();
        const strings = content.items.map(item => item.str);
        fullText += strings.join(" ") + "\n";
    }
    return fullText;
}

// Liaison avec votre interface
document.getElementById('pcFile').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    try {
        const text = await extractTextFromPDF(file);
        console.log("Texte de la PC extrait (longueur):", text.length);
        document.getElementById('aiOutput').innerHTML = 
            `<p class="text-emerald-600 font-medium">✅ Politique de Certification chargée (${text.length} caractères).</p>`;
        // Stockage temporaire pour l'IA
        window.currentPCContent = text; 
    } catch (err) {
        alert("Erreur PDF : " + err.message);
    }
});