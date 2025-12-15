describe('Test syncers', () => {
    beforeEach(()=>{
        cy.login();
    })
    const selector = {
        add: ".ant-table-title > div > .ant-btn"
      };
    it("test syncers", () => {
        cy.visit("http://localhost:7001/syncers");
        cy.url().should("eq", "http://localhost:7001/syncers");
        // Wait for page to be fully loaded and stable
        cy.wait(1000); // Give React time to complete all re-renders
        cy.get(selector.add,{timeout:10000}).should('be.visible').click({force: true});
        cy.url().should("include","http://localhost:7001/syncers/")
    });
})
