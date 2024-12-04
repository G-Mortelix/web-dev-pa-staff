document.addEventListener("DOMContentLoaded", function () {
    const searchInput = document.getElementById("search-input");

    searchInput.addEventListener("input", () => {
        const query = searchInput.value.toLowerCase(); // Get the search query
        filterFoldersAndFiles(query);
    });
});

function filterFoldersAndFiles(query) {
    const folderContainers = document.querySelectorAll(".folder-container");
    const subfolderContainers = document.querySelectorAll(".subfolder-item");
    const pdfItems = document.querySelectorAll(".pdf-item");

    let hasMatch = false;

    // Filter parent folders
    folderContainers.forEach(folder => {
        const folderName = folder.querySelector(".folder-name").textContent.toLowerCase();
        const folderMatches = folderName.includes(query);

        // Hide or show parent folder based on match
        folder.style.display = folderMatches ? "block" : "none";

        // If the folder matches, show it and its content
        if (folderMatches) {
            folder.style.display = "block";
            hasMatch = true;
        }
    });

    // Filter subfolders
    subfolderContainers.forEach(subfolder => {
        const subfolderName = subfolder.querySelector(".subfolder-name").textContent.toLowerCase();
        const subfolderMatches = subfolderName.includes(query);

        // Hide or show subfolder
        subfolder.style.display = subfolderMatches ? "block" : "none";

        // If the subfolder matches, ensure its parent is also visible
        if (subfolderMatches) {
            const parentFolder = subfolder.closest(".folder-container");
            if (parentFolder) {
                parentFolder.style.display = "block";
            }
            hasMatch = true;
        }
    });

    // Filter PDFs
    pdfItems.forEach(pdf => {
        const pdfName = pdf.querySelector("a").textContent.toLowerCase();
        const pdfMatches = pdfName.includes(query);

        // Hide or show PDF
        pdf.style.display = pdfMatches ? "block" : "none";

        // If a PDF matches, ensure its parent folder is also visible
        if (pdfMatches) {
            const parentFolder = pdf.closest(".folder-container");
            const parentSubfolder = pdf.closest(".subfolder-item");
            if (parentFolder) {
                parentFolder.style.display = "block";
            }
            if (parentSubfolder) {
                parentSubfolder.style.display = "block";
            }
            hasMatch = true;
        }
    });

    // If no matches, optionally display a "No results found" message
    if (!hasMatch) {
        console.log("No matches found");
    }
}
