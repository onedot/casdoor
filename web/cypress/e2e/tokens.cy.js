describe('Test tokens', () => {
    beforeEach(()=>{
        cy.login();
    })
    const selector = {
        add: ".ant-table-title > div > .ant-btn"
      };
    it("test records", () => {
        cy.visit("http://localhost:7001/tokens");
        cy.url().should("eq", "http://localhost:7001/tokens");
        // Wait for page to be fully loaded and stable
        cy.wait(1000); // Give React time to complete all re-renders
        cy.get(selector.add,{timeout:10000}).should('be.visible').click({force: true});
        cy.url().should("include","http://localhost:7001/tokens/")
    });
})
