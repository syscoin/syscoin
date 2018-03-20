#ifndef EDITOFFERDIALOG_H
#define EDITOFFERDIALOG_H

#include <QDialog>

namespace Ui {
    class EditOfferDialog;
}
class OfferTableModel;

QT_BEGIN_NAMESPACE
class QDataWidgetMapper;
QT_END_NAMESPACE

/** Dialog for editing an address and associated information.
 */
class EditOfferDialog : public QDialog
{
    Q_OBJECT

public:
    enum Mode {
        NewOffer = 0,
        EditOffer
    };

    explicit EditOfferDialog(Mode mode, QWidget *parent = 0);
    ~EditOfferDialog();

    void setModel(OfferTableModel *model);
    void loadRow(int row);
	QString getOffer() const;
public slots:
    void accept();

private:
    bool saveCurrentRow();

    Ui::EditOfferDialog *ui;
    QDataWidgetMapper *mapper;
    Mode mode;
    OfferTableModel *model;

    QString offer;
};

#endif // EDITOFFERDIALOG_H
