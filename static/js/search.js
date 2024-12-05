document.addEventListener("DOMContentLoaded", function () {
    const folderCardContainer = document.querySelector("[data-folder-container]");
    const searchInput = document.querySelector("[data-search]");
  
    let folders = [];
  
    // Search Functionality
    searchInput.addEventListener("input", e => {
      const value = e.target.value.toLowerCase();
      folders.forEach(folder => {
        const isVisible =
          folder.name.toLowerCase().includes(value) || // Check folder name
          folder.files.some(file => file.toLowerCase().includes(value)); // Check PDF names
        folder.element.classList.toggle("hide", !isVisible);
      });
    });
  
    // Fetch folder data from the backend
    fetch("/api/folders")
      .then(res => res.json())
      .then(data => {
        data.forEach(department => {
          const departmentElement = document.createElement("div");
          departmentElement.classList.add("department-container");
  
          const departmentHeader = document.createElement("h2");
          departmentHeader.classList.add("department-heading");
          departmentHeader.textContent = department.name;
  
          departmentElement.append(departmentHeader);
  
          department.folders.forEach(folder => {
            const folderCard = document.createElement("div");
            folderCard.classList.add("folder-card");
  
            const folderHeader = document.createElement("div");
            folderHeader.classList.add("folder-header");
            folderHeader.textContent = folder.name;
  
            const folderBody = document.createElement("div");
            folderBody.classList.add("folder-body");
            folderBody.innerHTML = folder.files
              .map(file => `<a href="#">${file}</a>`)
              .join("<br>");
  
            folderCard.append(folderHeader, folderBody);
            departmentElement.append(folderCard);
  
            // Save folder info for filtering
            folders.push({ name: folder.name, files: folder.files, element: folderCard });
          });
  
          folderCardContainer.append(departmentElement);
        });
      })
      .catch(error => console.error("Error fetching folder data:", error));
  });
  