document.addEventListener("DOMContentLoaded", function () {
    const folderElements = document.querySelectorAll(".folder-container");

    // Listen for clicks on each folder to load its content
    folderElements.forEach(folder => {
        folder.addEventListener("click", function () {
            const folderName = folder.querySelector(".folder-name").textContent;
            loadFolderContent(folderName);
        });
    });
});

// Load folder content dynamically (this includes subfolders, sub-subfolders, and files)
function loadFolderContent(folderName) {
    console.log(`Loading content for folder: ${folderName}`);

    // Fetch folder content from the backend or mock data
    fetch(`/folder-content/${folderName}`)
        .then(response => response.json())
        .then(data => {
            const folderContainer = document.getElementById(`${folderName}-content`);
            if (folderContainer) {
                folderContainer.innerHTML = ''; // Clear previous content

                // Render subfolders and sub-subfolders (3-tiered structure)
                data.subfolders.forEach(subfolder => {
                    const subfolderElement = document.createElement('div');
                    subfolderElement.className = 'subfolder-item';
                    subfolderElement.innerHTML = `
                        <span class="subfolder-name" onclick="loadFolderContent('${subfolder.folder_name}')">${subfolder.folder_name}</span>
                    `;

                    // Render sub-subfolders (nested under subfolders)
                    if (subfolder.subfolders && subfolder.subfolders.length > 0) {
                        subfolderElement.innerHTML += `
                            <div class="sub-subfolder-container" id="${subfolder.folder_name}-subsub">
                                ${renderSubSubfolders(subfolder.subfolders)}
                            </div>
                        `;
                    }

                    folderContainer.appendChild(subfolderElement);

                    // Render files (direct PDFs or documents)
                    subfolder.files.forEach(file => {
                        const fileElement = document.createElement('div');
                        fileElement.className = 'pdf-item';
                        fileElement.innerHTML = `<a href="#">${file}</a>`;
                        folderContainer.appendChild(fileElement);
                    });
                });
            } else {
                console.error(`Folder container for ${folderName} not found`);
            }
        })
        .catch(error => console.error('Error loading folder content:', error));
}

// Helper function to render sub-subfolders inside a subfolder
function renderSubSubfolders(subSubfolders) {
    return subSubfolders.map(subSubfolder => `
        <div class="sub-subfolder-item">
            <span class="sub-subfolder-name">${subSubfolder}</span>
        </div>
    `).join('');
}
